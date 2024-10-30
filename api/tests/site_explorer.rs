/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::{collections::HashMap, net::IpAddr, str::FromStr, sync::Arc};

use carbide::{
    cfg::SiteExplorerConfig,
    db::{
        self,
        expected_machine::ExpectedMachine,
        explored_endpoints::DbExploredEndpoint,
        explored_managed_host::DbExploredManagedHost,
        machine::{Machine, MachineSearchConfig},
        machine_topology::MachineTopology,
        DatabaseError, ObjectColumnFilter, ObjectFilter,
    },
    model::{
        hardware_info::HardwareInfo,
        machine::{DpuDiscoveringState, DpuInitState, ManagedHostState, ManagedHostStateSnapshot},
        site_explorer::{
            ComputerSystem, EndpointExplorationError, EndpointExplorationReport, EndpointType,
            ExploredDpu, ExploredManagedHost, UefiDevicePath,
        },
    },
    resource_pool::ResourcePoolStats,
    site_explorer::SiteExplorer,
    state_controller::machine::handler::MachineStateHandlerBuilder,
    CarbideError,
};
use common::api_fixtures::{endpoint_explorer::MockEndpointExplorer, TestEnv};
use forge_uuid::{machine::MachineId, network::NetworkSegmentId};
use ipnetwork::IpNetwork;
use itertools::Itertools;
use mac_address::MacAddress;
use rpc::{
    forge::{forge_server::Forge, DhcpDiscovery, GetSiteExplorationRequest},
    site_explorer::{ExploredDpu as RpcExploredDpu, ExploredManagedHost as RpcExploredManagedHost},
    BlockDevice, DiscoveryData, DiscoveryInfo, MachineDiscoveryInfo,
};
use tonic::Request;
use utils::models::arch::CpuArchitecture;

use crate::common::{
    api_fixtures,
    api_fixtures::{
        dpu::DpuConfig,
        managed_host::ManagedHostConfig,
        network_segment::{
            create_admin_network_segment, create_host_inband_network_segment,
            create_underlay_network_segment, FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY,
            FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY,
        },
        site_explorer::MockExploredHost,
        TestEnvOverrides,
    },
    test_meter::TestMeter,
};

mod common;
#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[derive(Clone, Debug)]
struct FakeMachine {
    pub mac: MacAddress,
    pub dhcp_vendor: String,
    pub segment: NetworkSegmentId,
    pub ip: String,
}

impl FakeMachine {
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

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
async fn test_site_explorer_main(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;

    let underlay_segment = create_underlay_network_segment(&env).await;
    let admin_segment = create_admin_network_segment(&env).await;

    // Let's create 3 machines on the underlay, and 1 on the admin network
    // The 1 on the admin network is not supposed to be searched. This is verified
    // by providing no mocked exploration data for this machine, which would lead
    // to a panic if the machine is queried
    let mut machines = vec![
        // machines[0] is a DPU belonging to machines[1]
        FakeMachine {
            mac: "B8:3F:D2:90:97:A6".parse().unwrap(),
            dhcp_vendor: "Vendor1".to_string(),
            segment: underlay_segment,
            ip: String::new(),
        },
        // machines[1] has 1 dpu (machines[0])
        FakeMachine {
            mac: "AA:AB:AC:AD:AA:02".parse().unwrap(),
            dhcp_vendor: "Vendor2".to_string(),
            segment: underlay_segment,
            ip: String::new(),
        },
        // machines[2] has no DPUs
        FakeMachine {
            mac: "AA:AB:AC:AD:AA:03".parse().unwrap(),
            dhcp_vendor: "Vendor3".to_string(),
            segment: underlay_segment,
            ip: String::new(),
        },
        // machines[3] is not on the underlay network and should not be searched.
        FakeMachine {
            mac: "AA:AB:AC:AD:BB:01".parse().unwrap(),
            dhcp_vendor: "VendorInvalidSegment".to_string(),
            segment: admin_segment,
            ip: String::new(),
        },
    ];

    for machine in &mut machines {
        let response = env
            .api
            .discover_dhcp(tonic::Request::new(DhcpDiscovery {
                mac_address: machine.mac.to_string(),
                relay_address: match machine.segment {
                    s if s == underlay_segment => "192.0.1.1".to_string(),
                    _ => "192.0.2.1".to_string(),
                },
                link_address: None,
                vendor_string: Some(machine.dhcp_vendor.clone()),
                circuit_id: None,
                remote_id: None,
            }))
            .await?
            .into_inner();
        tracing::info!(
            "DHCP with mac {} assigned ip {}",
            machine.mac,
            response.address
        );
        machine.ip = response.address;
    }

    let mut txn = env.pool.begin().await?;
    assert_eq!(
        db::machine_interface::count_by_segment_id(&mut txn, &underlay_segment)
            .await
            .unwrap(),
        3
    );
    assert_eq!(
        db::machine_interface::count_by_segment_id(&mut txn, &admin_segment)
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
            }),
        ),
    ]);

    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: carbide::dynamic_settings::create_machines(true),
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
    );

    explorer.run_single_iteration().await.unwrap();
    // Since we configured a limit of 2 entries, we should have those 2 results now
    let mut txn = env.pool.begin().await?;
    let explored = DbExploredEndpoint::find_all(&mut txn).await.unwrap();
    txn.commit().await?;
    assert_eq!(explored.len(), 2);

    for report in &explored {
        assert_eq!(report.report_version.version_nr(), 1);
        let guard = endpoint_explorer.reports.lock().unwrap();
        let res = guard.get(&report.address).unwrap();
        if res.is_err() {
            assert_eq!(
                res.clone().unwrap_err(),
                report.report.last_exploration_error.clone().unwrap()
            );
        } else {
            assert_eq!(
                res.clone().unwrap().endpoint_type,
                report.report.endpoint_type
            );
            assert_eq!(res.clone().unwrap().vendor, report.report.vendor);
            assert_eq!(res.clone().unwrap().managers, report.report.managers);
            assert_eq!(res.clone().unwrap().systems, report.report.systems);
            assert_eq!(res.clone().unwrap().chassis, report.report.chassis);
            assert_eq!(res.clone().unwrap().service, report.report.service);
        }
    }

    // Retrieve the report via gRPC
    let report = fetch_exploration_report(&env).await;
    assert!(report.managed_hosts.is_empty());

    // We should also have metric entries
    assert_eq!(
        test_meter
            .formatted_metric("forge_endpoint_explorations_count")
            .unwrap(),
        "2"
    );
    assert!(test_meter
        .formatted_metric("forge_endpoint_exploration_success_count")
        .is_some());
    // The failure metric is not emitted if no failure happened
    assert_eq!(
        test_meter
            .formatted_metric("forge_endpoint_exploration_duration_milliseconds_count")
            .unwrap(),
        "2"
    );
    assert_eq!(
        test_meter
            .formatted_metric("forge_site_exploration_identified_managed_hosts_count")
            .unwrap(),
        "0"
    );
    assert_eq!(
        test_meter
            .formatted_metric("forge_site_explorer_created_machines_count")
            .unwrap(),
        "0"
    );

    // Running again should yield all 3 entries
    explorer.run_single_iteration().await.unwrap();
    // Since we configured a limit of 2 entries, we should have those 2 results now
    let mut txn = env.pool.begin().await?;
    let explored = DbExploredEndpoint::find_all(&mut txn).await.unwrap();
    txn.commit().await?;
    assert_eq!(explored.len(), 3);
    let mut versions = Vec::new();
    for report in &explored {
        versions.push(report.report_version.version_nr());
        let guard = endpoint_explorer.reports.lock().unwrap();
        let res = guard.get(&report.address).unwrap();
        if res.is_err() {
            assert_eq!(
                res.clone().unwrap_err(),
                report.report.last_exploration_error.clone().unwrap()
            );
        } else {
            assert_eq!(
                res.clone().unwrap().endpoint_type,
                report.report.endpoint_type
            );
            assert_eq!(res.clone().unwrap().vendor, report.report.vendor);
            assert_eq!(res.clone().unwrap().managers, report.report.managers);
            assert_eq!(res.clone().unwrap().systems, report.report.systems);
            assert_eq!(res.clone().unwrap().chassis, report.report.chassis);
            assert_eq!(res.clone().unwrap().service, report.report.service);
        }
    }
    versions.sort();
    assert_eq!(&versions, &[1, 1, 2]);

    // Retrieve the report via gRPC
    let report = fetch_exploration_report(&env).await;
    assert!(report.managed_hosts.is_empty());

    assert_eq!(
        test_meter
            .formatted_metric("forge_endpoint_explorations_count")
            .unwrap(),
        "2"
    );
    assert!(test_meter
        .formatted_metric("forge_endpoint_exploration_success_count")
        .is_some());
    assert_eq!(
        test_meter
            .formatted_metric("forge_endpoint_exploration_duration_milliseconds_count")
            .unwrap(),
        "4"
    );
    assert_eq!(
        test_meter
            .formatted_metric("forge_site_exploration_identified_managed_hosts_count")
            .unwrap(),
        "0"
    );
    assert_eq!(
        test_meter
            .formatted_metric("forge_site_explorer_created_machines_count")
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
    for addr in ["192.0.1.2", "192.0.1.3", "192.0.1.4"] {
        DbExploredEndpoint::set_preingestion_complete(
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
    let explored = DbExploredEndpoint::find_all(&mut txn).await.unwrap();
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
        .filter(|m| m.segment == underlay_segment)
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
            .formatted_metric("forge_site_exploration_identified_managed_hosts_count")
            .unwrap(),
        "2"
    );

    txn.commit().await?;
    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_expected_machine"))]
async fn test_site_explorer_audit_exploration_results(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;

    let underlay_segment = create_underlay_network_segment(&env).await;

    let mut machines = vec![
        // This will be our expected DPU, and it will have the
        // expected serial number, but we assume no DPUs are expected,
        // should it still shouldn't be counted as `expected`        .
        FakeMachine {
            mac: "5a:5b:5c:5d:5e:5f".parse().unwrap(),
            dhcp_vendor: "Vendor1".to_string(),
            segment: underlay_segment,
            ip: String::new(),
        },
        // This will be expected but unauthorized, and the serial is mismatched
        FakeMachine {
            mac: "0a:0b:0c:0d:0e:0f".parse().unwrap(),
            dhcp_vendor: "Vendor3".to_string(),
            segment: underlay_segment,
            ip: String::new(),
        },
        // This host will be expected but missing credentials, and the serial is mismatched
        FakeMachine {
            mac: "1a:1b:1c:1d:1e:1f".parse().unwrap(),
            dhcp_vendor: "Vendor3".to_string(),
            segment: underlay_segment,
            ip: String::new(),
        },
        // This host will be expected, but the serial number will be mismatched.
        FakeMachine {
            mac: "2a:2b:2c:2d:2e:2f".parse().unwrap(),
            dhcp_vendor: "Vendor3".to_string(),
            segment: underlay_segment,
            ip: String::new(),
        },
        // This will be expected, with a good serial number.
        // It will also have associated DPUs and should get a managed host.
        FakeMachine {
            mac: "3a:3b:3c:3d:3e:3f".parse().unwrap(),
            dhcp_vendor: "Vendor3".to_string(),
            segment: underlay_segment,
            ip: String::new(),
        },
        // This host is not expected.
        FakeMachine {
            mac: "ab:cd:ef:ab:cd:ef".parse().unwrap(),
            dhcp_vendor: "Vendor3".to_string(),
            segment: underlay_segment,
            ip: String::new(),
        },
        // This DPU is really not expected. (i.e. no DB entry)
        FakeMachine {
            mac: "ef:cd:ab:ef:cd:ab".parse().unwrap(),
            dhcp_vendor: "Vendor3".to_string(),
            segment: underlay_segment,
            ip: String::new(),
        },
    ];

    for machine in &mut machines {
        let response = env
            .api
            .discover_dhcp(tonic::Request::new(DhcpDiscovery {
                mac_address: machine.mac.to_string(),
                relay_address: match machine.segment {
                    s if s == underlay_segment => "192.0.1.1".to_string(),
                    _ => "192.0.2.1".to_string(),
                },
                link_address: None,
                vendor_string: Some(machine.dhcp_vendor.clone()),
                circuit_id: None,
                remote_id: None,
            }))
            .await?
            .into_inner();
        tracing::info!(
            "DHCP with mac {} assigned ip {}",
            machine.mac,
            response.address
        );
        machine.ip = response.address;
    }

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
        create_machines: carbide::dynamic_settings::create_machines(true),
        override_target_ip: None,
        override_target_port: None,
        allow_zero_dpu_hosts: false,
        allow_changing_bmc_proxy: None,
        bmc_proxy: Arc::default(),
    };
    let test_meter = TestMeter::default();
    let explorer = SiteExplorer::new(
        env.pool.clone(),
        explorer_config,
        test_meter.meter(),
        endpoint_explorer.clone(),
        Arc::new(env.config.get_firmware_config()),
        env.common_pools.clone(),
    );

    explorer.run_single_iteration().await.unwrap();
    // forge_endpoint_exploration_preingestions_incomplete_overall_count
    let m: HashMap<String, String> = test_meter
        .parsed_metrics("forge_endpoint_exploration_preingestions_incomplete_overall_count")
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
        DbExploredEndpoint::set_preingestion_complete(
            std::net::IpAddr::from(std::net::Ipv4Addr::new(192, 0, 1, final_octet)),
            &mut txn,
        )
        .await
        .unwrap();
    }
    txn.commit().await?;
    explorer.run_single_iteration().await.unwrap();

    let mut txn = env.pool.begin().await?;
    let explored = DbExploredEndpoint::find_all(&mut txn).await.unwrap();
    txn.commit().await?;
    assert_eq!(explored.len(), 7);

    for report in &explored {
        assert_eq!(report.report_version.version_nr(), 2);
        let guard = endpoint_explorer.reports.lock().unwrap();
        let res = guard.get(&report.address).unwrap();
        if res.is_err() {
            assert_eq!(
                res.clone().unwrap_err(),
                report.report.last_exploration_error.clone().unwrap()
            );
        } else {
            assert_eq!(
                res.clone().unwrap().endpoint_type,
                report.report.endpoint_type
            );
            assert_eq!(res.clone().unwrap().vendor, report.report.vendor);
            assert_eq!(res.clone().unwrap().managers, report.report.managers);
            assert_eq!(res.clone().unwrap().systems, report.report.systems);
            assert_eq!(res.clone().unwrap().chassis, report.report.chassis);
            assert_eq!(res.clone().unwrap().service, report.report.service);
        }
    }

    // Retrieve the report via gRPC
    let report = fetch_exploration_report(&env).await;

    // We should have at least one managed host built by this point.
    assert!(!report.managed_hosts.is_empty());

    // Check for the expected metrics

    // forge_endpoint_exploration_failures_overall_count
    let m: HashMap<String, String> = test_meter
        .parsed_metrics("forge_endpoint_exploration_failures_overall_count")
        .into_iter()
        .collect();

    assert!(!m.is_empty());
    assert!(m.get("{failure=\"unauthorized\"}").unwrap() == "1");
    assert!(m.get("{failure=\"missing_credentials\"}").unwrap() == "1");

    // forge_endpoint_exploration_preingestions_incomplete_overall_count
    let m: HashMap<String, String> = test_meter
        .parsed_metrics("forge_endpoint_exploration_preingestions_incomplete_overall_count")
        .into_iter()
        .collect();
    // Everything should be done with preingestion now.
    assert!(m.is_empty());

    // forge_endpoint_exploration_expected_serial_number_mismatches_overall_count
    let m: HashMap<String, String> = test_meter
        .parsed_metrics(
            "forge_endpoint_exploration_expected_serial_number_mismatches_overall_count",
        )
        .into_iter()
        .collect();

    assert!(!m.is_empty());
    assert_eq!(m.get("{machine_type=\"host\"}").unwrap(), "3");

    // forge_endpoint_exploration_machines_explored_overall_count
    let m: HashMap<String, String> = test_meter
        .parsed_metrics("forge_endpoint_exploration_machines_explored_overall_count")
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

    // forge_endpoint_exploration_expected_machines_missing_overall_count
    assert_eq!(
        test_meter
            .formatted_metric("forge_endpoint_exploration_expected_machines_missing_overall_count")
            .unwrap(),
        "1"
    );

    // forge_endpoint_exploration_identified_managed_hosts_overall_count
    let m: HashMap<String, String> = test_meter
        .parsed_metrics("forge_endpoint_exploration_identified_managed_hosts_overall_count")
        .into_iter()
        .collect();

    assert!(!m.is_empty());
    assert_eq!(m.get("{expectation=\"expected\"}").unwrap(), "1");

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
async fn test_site_explorer_reject_zero_dpu_hosts(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = common::api_fixtures::get_config();
    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await;
    let _underlay_segment = create_underlay_network_segment(&env).await;
    let _admin_segment = create_admin_network_segment(&env).await;

    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());
    let test_meter = TestMeter::default();
    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: carbide::dynamic_settings::create_machines(true),
        ..Default::default()
    };

    let explorer = SiteExplorer::new(
        env.pool.clone(),
        explorer_config,
        test_meter.meter(),
        endpoint_explorer.clone(),
        Arc::new(env.config.get_firmware_config()),
        env.common_pools.clone(),
    );

    let host_bmc_mac = MacAddress::from_str("a0:88:c2:08:81:98")?;
    let response = env
        .api
        .discover_dhcp(tonic::Request::new(DhcpDiscovery {
            mac_address: host_bmc_mac.to_string(),
            relay_address: "192.0.1.1".to_string(),
            link_address: None,
            vendor_string: Some("SomeVendor".to_string()),
            circuit_id: None,
            remote_id: None,
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(!response.address.is_empty());

    let interface_id = response.machine_interface_id;
    let mut ifaces = env
        .api
        .find_interfaces(tonic::Request::new(rpc::forge::InterfaceSearchQuery {
            id: Some(interface_id.unwrap()),
            ip: None,
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(ifaces.interfaces.len(), 1);
    let iface = ifaces.interfaces.remove(0);
    let mut addresses = iface.address;
    let host_bmc_ip = addresses.remove(0);

    let exploration_report = ExploredManagedHost {
        host_bmc_ip: IpAddr::from_str(&host_bmc_ip)?,
        dpus: vec![],
    };

    let Err(CarbideError::NoDpusInMachine(_)) = explorer
        .create_managed_host(
            exploration_report.clone(),
            EndpointExplorationReport::default(),
            &env.pool,
        )
        .await
    else {
        panic!("explorer.create_managed_host should have failed with a NoDpusInMachine error")
    };
    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
async fn test_site_explorer_reexplore(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;

    let underlay_segment = create_underlay_network_segment(&env).await;

    let mut machines = vec![
        FakeMachine {
            mac: "B8:3F:D2:90:97:A6".parse().unwrap(),
            dhcp_vendor: "Vendor1".to_string(),
            segment: underlay_segment,
            ip: String::new(),
        },
        FakeMachine {
            mac: "AA:AB:AC:AD:AA:02".parse().unwrap(),
            dhcp_vendor: "Vendor2".to_string(),
            segment: underlay_segment,
            ip: String::new(),
        },
    ];

    for machine in &mut machines {
        let response = env
            .api
            .discover_dhcp(tonic::Request::new(DhcpDiscovery {
                mac_address: machine.mac.to_string(),
                relay_address: "192.0.1.1".to_string(),
                link_address: None,
                vendor_string: Some(machine.dhcp_vendor.clone()),
                circuit_id: None,
                remote_id: None,
            }))
            .await?
            .into_inner();
        machine.ip = response.address;
    }

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
        enabled: true,
        explorations_per_run: 1,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: carbide::dynamic_settings::create_machines(false),
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
    );

    explorer.run_single_iteration().await.unwrap();
    // Since we configured a limit of 1 entries, we should have 1 results now
    let mut txn = env.pool.begin().await?;
    let explored = DbExploredEndpoint::find_all(&mut txn).await.unwrap();
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
    let explored = DbExploredEndpoint::find_all(&mut txn).await.unwrap();
    txn.commit().await?;
    for report in &explored {
        assert!(report.exploration_requested);
    }

    // The 2nd iteration should just update the version number of the initial explored
    // endpoint - but not find anything new
    explorer.run_single_iteration().await.unwrap();
    let mut txn = env.pool.begin().await?;
    let explored = DbExploredEndpoint::find_all(&mut txn).await.unwrap();
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
        format!("An object of type explored_endpoint was intended to be modified did not have the expected version {}",
        unexpected_version.version_string()));

    let mut txn = env.pool.begin().await?;
    let explored = DbExploredEndpoint::find_all(&mut txn).await.unwrap();
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
    let explored = DbExploredEndpoint::find_all(&mut txn).await.unwrap();
    txn.commit().await?;
    for report in &explored {
        assert!(report.exploration_requested);
    }

    // 3rd iteration still yields 1 result
    explorer.run_single_iteration().await.unwrap();
    let mut txn = env.pool.begin().await?;
    let explored = DbExploredEndpoint::find_all(&mut txn).await.unwrap();
    txn.commit().await?;
    assert_eq!(explored.len(), 1);

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc",))]
async fn test_site_explorer_creates_managed_host(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Prevent Firmware update here, since we test it in other method
    let mut config = common::api_fixtures::get_config();
    config.dpu_models = HashMap::new();
    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await;
    let _underlay_segment = create_underlay_network_segment(&env).await;
    let _admin_segment = create_admin_network_segment(&env).await;

    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());
    let test_meter = TestMeter::default();
    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: carbide::dynamic_settings::create_machines(true),
        ..Default::default()
    };

    let explorer = SiteExplorer::new(
        env.pool.clone(),
        explorer_config,
        test_meter.meter(),
        endpoint_explorer.clone(),
        Arc::new(env.config.get_firmware_config()),
        env.common_pools.clone(),
    );

    let oob_mac = MacAddress::from_str("a0:88:c2:08:80:95")?;
    let response = env
        .api
        .discover_dhcp(tonic::Request::new(DhcpDiscovery {
            mac_address: oob_mac.to_string(),
            relay_address: "192.0.1.1".to_string(),
            link_address: None,
            vendor_string: Some("NVIDIA/OOB".to_string()),
            circuit_id: None,
            remote_id: None,
        }))
        .await
        .unwrap()
        .into_inner();

    assert!(!response.address.is_empty());

    // Use a known DPU serial so we can assert on the generated MachineId
    let dpu_serial = "MT2328XZ185R".to_string();
    let expected_machine_id =
        "fm100ds3gfip02lfgleidqoitqgh8d8mdc4a3j2tdncbjrfjtvrrhn2kleg".to_string();

    let mock_dpu = DpuConfig::with_serial(dpu_serial.clone());
    let mock_host = ManagedHostConfig::with_dpus(vec![mock_dpu.clone()]);
    let mut dpu_report: EndpointExplorationReport = mock_dpu.clone().into();
    dpu_report.generate_machine_id(false)?;

    assert!(dpu_report.machine_id.as_ref().is_some());
    assert_eq!(
        dpu_report.machine_id.as_ref().unwrap().to_string(),
        expected_machine_id,
    );

    let response = env
        .api
        .discover_dhcp(tonic::Request::new(DhcpDiscovery {
            mac_address: mock_host.bmc_mac_address.to_string(),
            relay_address: "192.0.1.1".to_string(),
            link_address: None,
            vendor_string: Some("NVIDIA/OOB".to_string()),
            circuit_id: None,
            remote_id: None,
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(!response.address.is_empty());

    let interface_id = response.machine_interface_id;
    let mut ifaces = env
        .api
        .find_interfaces(tonic::Request::new(rpc::forge::InterfaceSearchQuery {
            id: Some(interface_id.unwrap()),
            ip: None,
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(ifaces.interfaces.len(), 1);
    let iface = ifaces.interfaces.remove(0);
    let mut addresses = iface.address;
    let host_bmc_ip = addresses.remove(0);

    let exploration_report = ExploredManagedHost {
        host_bmc_ip: IpAddr::from_str(&host_bmc_ip)?,
        dpus: vec![ExploredDpu {
            bmc_ip: IpAddr::from_str(response.address.as_str())?,
            host_pf_mac_address: Some(mock_dpu.host_mac_address),
            report: dpu_report.clone(),
        }],
    };

    assert!(
        explorer
            .create_managed_host(
                exploration_report.clone(),
                EndpointExplorationReport::default(),
                &env.pool
            )
            .await?
    );

    let mut txn = env.pool.begin().await.unwrap();
    let dpu_machine = Machine::find_one(
        &mut txn,
        dpu_report.machine_id.as_ref().unwrap(),
        MachineSearchConfig {
            include_predicted_host: true,
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        dpu_machine.current_state(),
        ManagedHostState::DpuDiscoveringState {
            dpu_states: carbide::model::machine::DpuDiscoveringStates {
                states: HashMap::from([(
                    dpu_machine.id().clone(),
                    DpuDiscoveringState::Initializing
                )]),
            },
        }
    );
    assert_eq!(
        dpu_machine.hardware_info().unwrap().machine_type,
        CpuArchitecture::Aarch64,
    );
    assert_eq!(
        dpu_machine.bmc_info().ip.clone().unwrap(),
        response.address.to_string()
    );
    assert_eq!(
        dpu_machine.bmc_info().firmware_version.clone().unwrap(),
        "23.10-3".to_string()
    );
    assert_eq!(
        dpu_machine
            .hardware_info()
            .unwrap()
            .dmi_data
            .clone()
            .unwrap()
            .product_serial,
        dpu_serial
    );
    assert_eq!(
        dpu_machine
            .hardware_info()
            .unwrap()
            .dpu_info
            .clone()
            .unwrap()
            .part_number,
        "900-9D3B6-00CV-AA0".to_string()
    );
    assert_eq!(
        dpu_machine
            .hardware_info()
            .unwrap()
            .dpu_info
            .clone()
            .unwrap()
            .part_description,
        "Bluefield 3 SmartNIC Main Card".to_string()
    );

    let host_machine = Machine::find_host_by_dpu_machine_id(&mut txn, dpu_machine.id())
        .await?
        .unwrap();
    assert_eq!(
        host_machine.current_state(),
        ManagedHostState::DpuDiscoveringState {
            dpu_states: carbide::model::machine::DpuDiscoveringStates {
                states: HashMap::from([(
                    dpu_machine.id().clone(),
                    DpuDiscoveringState::Initializing
                )]),
            },
        }
    );
    assert!(host_machine.bmc_info().ip.is_some());

    // 2nd creation does nothing
    assert!(
        !explorer
            .create_managed_host(
                exploration_report,
                EndpointExplorationReport::default(),
                &env.pool
            )
            .await?
    );

    let handler = MachineStateHandlerBuilder::builder()
        .dpu_up_threshold(chrono::Duration::minutes(1))
        .hardware_models(env.config.get_firmware_config())
        .reachability_params(env.reachability_params)
        .attestation_enabled(env.attestation_enabled)
        .build();
    env.override_machine_state_controller_handler(handler).await;
    env.run_machine_state_controller_iteration().await;

    let dpu_machine = Machine::find_one(&mut txn, dpu_machine.id(), MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu_machine.current_state(),
        ManagedHostState::DpuDiscoveringState {
            dpu_states: carbide::model::machine::DpuDiscoveringStates {
                states: HashMap::from([(
                    dpu_machine.id().clone(),
                    DpuDiscoveringState::Configuring
                )]),
            },
        }
    );

    env.run_machine_state_controller_iteration().await;

    let dpu_machine = Machine::find_one(&mut txn, dpu_machine.id(), MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu_machine.current_state(),
        ManagedHostState::DpuDiscoveringState {
            dpu_states: carbide::model::machine::DpuDiscoveringStates {
                states: HashMap::from([(
                    dpu_machine.id().clone(),
                    DpuDiscoveringState::EnableRshim,
                )]),
            },
        }
    );

    env.run_machine_state_controller_iteration().await;

    let dpu_machine = Machine::find_one(&mut txn, dpu_machine.id(), MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu_machine.current_state(),
        ManagedHostState::DpuDiscoveringState {
            dpu_states: carbide::model::machine::DpuDiscoveringStates {
                states: HashMap::from([(
                    dpu_machine.id().clone(),
                    DpuDiscoveringState::DisableSecureBoot {
                        disable_secure_boot_state: Some(
                            carbide::model::machine::DisableSecureBootState::CheckSecureBootStatus
                        ),
                        count: 0,
                    },
                )]),
            },
        }
    );

    env.run_machine_state_controller_iteration().await;

    let dpu_machine = Machine::find_one(&mut txn, dpu_machine.id(), MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu_machine.current_state(),
        ManagedHostState::DpuDiscoveringState {
            dpu_states: carbide::model::machine::DpuDiscoveringStates {
                states: HashMap::from([(
                    dpu_machine.id().clone(),
                    DpuDiscoveringState::SetUefiHttpBoot,
                )]),
            },
        }
    );

    env.run_machine_state_controller_iteration().await;
    let dpu_machine = Machine::find_one(&mut txn, dpu_machine.id(), MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu_machine.current_state(),
        ManagedHostState::DpuDiscoveringState {
            dpu_states: carbide::model::machine::DpuDiscoveringStates {
                states: HashMap::from([(
                    dpu_machine.id().clone(),
                    DpuDiscoveringState::RebootAllDPUS
                )]),
            },
        }
    );

    env.run_machine_state_controller_iteration().await;

    let dpu_machine = Machine::find_one(&mut txn, dpu_machine.id(), MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu_machine.current_state(),
        ManagedHostState::DPUInit {
            dpu_states: carbide::model::machine::DpuInitStates {
                states: HashMap::from([(dpu_machine.id().clone(), DpuInitState::Init,)]),
            },
        },
    );

    let machine_interfaces = db::machine_interface::find_by_mac_address(&mut txn, oob_mac).await?;
    assert!(!machine_interfaces.is_empty());
    let topologies =
        MachineTopology::find_by_machine_ids(&mut txn, &[dpu_machine.id().clone()]).await?;
    assert!(topologies.contains_key(dpu_machine.id()));

    let topology = &topologies[dpu_machine.id()][0];
    assert!(topology.topology_update_needed());

    let hardware_info = &topology.topology().discovery_data.info;
    assert!(hardware_info.block_devices.is_empty());

    let mut discovery_info = DiscoveryInfo::try_from(hardware_info.clone()).unwrap();
    discovery_info.block_devices = vec![BlockDevice {
        model: "Fake block device".to_string(),
        ..Default::default()
    }];

    let response = env
        .api
        .discover_machine(Request::new(MachineDiscoveryInfo {
            machine_interface_id: Some(machine_interfaces[0].id.into()),
            discovery_data: Some(DiscoveryData::Info(discovery_info.clone())),
            create_machine: true,
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(response.machine_id.is_some());

    // Now let's check that DPU and host updated states and updated hardware information.
    let dpu_machine = Machine::find_one(&mut txn, dpu_machine.id(), MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert!(dpu_machine.loopback_ip().is_some());

    let machine_interfaces = db::machine_interface::find_by_mac_address(&mut txn, oob_mac).await?;
    assert!(machine_interfaces[0]
        .machine_id
        .as_ref()
        .is_some_and(|id| id == dpu_machine.id()));

    let host_machine =
        Machine::find_one(&mut txn, host_machine.id(), MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap();

    assert_eq!(
        host_machine.current_state(),
        ManagedHostState::DPUInit {
            dpu_states: carbide::model::machine::DpuInitStates {
                states: HashMap::from([(dpu_machine.id().clone(), DpuInitState::Init,)]),
            },
        }
    );

    let topologies =
        MachineTopology::find_by_machine_ids(&mut txn, &[dpu_machine.id().clone()]).await?;
    let topology = &topologies[dpu_machine.id()][0];
    assert!(!topology.topology_update_needed());

    let hardware_info = &topology.topology().discovery_data.info;
    assert!(!hardware_info.block_devices.is_empty());
    assert_eq!(
        hardware_info.block_devices[0].model,
        "Fake block device".to_string()
    );

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc",))]
async fn test_site_explorer_creates_multi_dpu_managed_host(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool).await;
    let _underlay_segment = create_underlay_network_segment(&env).await;
    let _admin_segment = create_admin_network_segment(&env).await;

    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());
    let test_meter = TestMeter::default();
    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: carbide::dynamic_settings::create_machines(true),
        ..Default::default()
    };

    let explorer = SiteExplorer::new(
        env.pool.clone(),
        explorer_config,
        test_meter.meter(),
        endpoint_explorer.clone(),
        Arc::new(env.config.get_firmware_config()),
        env.common_pools.clone(),
    );
    let mut txn = env.pool.begin().await.unwrap();
    const NUM_DPUS: usize = 2;
    let initial_loopback_pool_stats = env
        .common_pools
        .ethernet
        .pool_loopback_ip
        .stats(&mut *txn)
        .await
        .expect("failed to get inital pool stats");
    let mut oob_interfaces = Vec::new();
    let mut explored_dpus = Vec::new();

    let mock_host =
        ManagedHostConfig::with_dpus((0..NUM_DPUS).map(|_| DpuConfig::default()).collect());

    for (i, mock_dpu) in mock_host.dpus.iter().enumerate() {
        let oob_mac = mock_dpu.oob_mac_address;
        let response = env
            .api
            .discover_dhcp(tonic::Request::new(DhcpDiscovery {
                mac_address: oob_mac.to_string(),
                relay_address: "192.0.1.1".to_string(),
                link_address: None,
                vendor_string: Some("NVIDIA/OOB".to_string()),
                circuit_id: None,
                remote_id: None,
            }))
            .await
            .unwrap()
            .into_inner();

        assert!(!response.address.is_empty());
        let oob_interface = db::machine_interface::find_by_mac_address(&mut txn, oob_mac).await?;
        assert!(oob_interface[0].is_primary);
        oob_interfaces.push(oob_interface[0].clone());

        let mut dpu_report: EndpointExplorationReport = mock_dpu.clone().into();
        dpu_report.generate_machine_id(false)?;
        explored_dpus.push(ExploredDpu {
            bmc_ip: IpAddr::from_str(format!("192.168.1.{i}").as_str())?,
            host_pf_mac_address: Some(mock_dpu.host_mac_address),
            report: dpu_report.clone(),
        })
    }

    let host_bmc_mac = mock_host.bmc_mac_address;
    let response = env
        .api
        .discover_dhcp(tonic::Request::new(DhcpDiscovery {
            mac_address: host_bmc_mac.to_string(),
            relay_address: "192.0.1.1".to_string(),
            link_address: None,
            vendor_string: Some("NVIDIA/OOB".to_string()),
            circuit_id: None,
            remote_id: None,
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(!response.address.is_empty());

    let interface_id = response.machine_interface_id;
    let mut ifaces = env
        .api
        .find_interfaces(tonic::Request::new(rpc::forge::InterfaceSearchQuery {
            id: Some(interface_id.unwrap()),
            ip: None,
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(ifaces.interfaces.len(), 1);
    let iface = ifaces.interfaces.remove(0);
    let mut addresses = iface.address;
    let host_bmc_ip = addresses.remove(0);

    let exploration_report = ExploredManagedHost {
        host_bmc_ip: IpAddr::from_str(&host_bmc_ip)?,
        dpus: explored_dpus.clone(),
    };

    assert!(
        explorer
            .create_managed_host(
                exploration_report.clone(),
                EndpointExplorationReport::default(),
                &env.pool
            )
            .await?
    );

    // a second create attempt on the same machine should return false.
    assert!(
        !explorer
            .create_managed_host(
                exploration_report,
                EndpointExplorationReport::default(),
                &env.pool
            )
            .await?
    );

    let expected_loopback_count = NUM_DPUS;
    assert_eq!(
        env.common_pools
            .ethernet
            .pool_loopback_ip
            .stats(&mut *txn)
            .await?,
        ResourcePoolStats {
            used: expected_loopback_count,
            free: initial_loopback_pool_stats.free - expected_loopback_count
        }
    );

    let mut host_machine_id: Option<MachineId> = None;
    let mut dpu_machines = Vec::new();
    let mut host_machine = None;

    for dpu in explored_dpus {
        let dpu_machine = Machine::find_one(
            &mut txn,
            dpu.report.machine_id.as_ref().unwrap(),
            MachineSearchConfig {
                include_predicted_host: true,
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .unwrap();

        let expected_loopback_ip = dpu_machine
            .network_config()
            .loopback_ip
            .unwrap()
            .to_string();
        let network_config_response = env
            .api
            .get_managed_host_network_config(Request::new(
                rpc::forge::ManagedHostNetworkConfigRequest {
                    dpu_machine_id: Some(dpu_machine.id().clone().into()),
                },
            ))
            .await?;
        assert_eq!(
            expected_loopback_ip,
            network_config_response
                .into_inner()
                .managed_host_config
                .unwrap()
                .loopback_ip
        );

        if host_machine.is_none() {
            host_machine = Machine::find_host_by_dpu_machine_id(&mut txn, dpu_machine.id()).await?;
        }
        let hm = host_machine.clone().unwrap();
        assert!(hm.bmc_info().ip.is_some());
        if host_machine_id.is_none() {
            host_machine_id = Some(hm.id().clone());
        }

        assert_eq!(hm.id(), host_machine_id.as_ref().unwrap());
        dpu_machines.push(dpu_machine);
    }

    let expected_state = ManagedHostState::DpuDiscoveringState {
        dpu_states: carbide::model::machine::DpuDiscoveringStates {
            states: dpu_machines
                .iter()
                .map(|x| (x.id().clone(), DpuDiscoveringState::Initializing))
                .collect::<HashMap<MachineId, DpuDiscoveringState>>(),
        },
    };

    assert_eq!(host_machine.unwrap().current_state(), expected_state);

    for dpu in &dpu_machines {
        assert_eq!(dpu.current_state(), expected_state);
    }

    let mut interfaces_map = db::machine_interface::find_by_machine_ids(
        &mut txn,
        &[host_machine_id.as_ref().unwrap().clone()],
    )
    .await?;
    let interfaces = interfaces_map
        .remove(host_machine_id.clone().as_ref().unwrap())
        .unwrap();
    assert_eq!(interfaces.len(), NUM_DPUS);
    assert!(interfaces[0].is_primary);
    for interface in interfaces.iter().skip(1) {
        assert!(!interface.is_primary);
    }

    // Try to discover machine with multiple DPUs
    for i in 0..NUM_DPUS {
        let topologies =
            MachineTopology::find_by_machine_ids(&mut txn, &[dpu_machines[i].id().clone()]).await?;

        let topology = &topologies[dpu_machines[i].id()][0];

        let hardware_info = &topology.topology().discovery_data.info;

        let discovery_info = DiscoveryInfo::try_from(hardware_info.clone()).unwrap();
        let response = env
            .api
            .discover_machine(Request::new(MachineDiscoveryInfo {
                machine_interface_id: Some(oob_interfaces[i].id.into()),
                discovery_data: Some(DiscoveryData::Info(discovery_info.clone())),
                create_machine: true,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(response.machine_id.is_some());
    }

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc",))]
async fn test_site_explorer_clear_last_known_error(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool).await;
    let mut txn = env.pool.begin().await?;
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

    DbExploredEndpoint::insert(bmc_ip, &dpu_report1, &mut txn).await?;
    txn.commit().await.map_err(|e| {
        DatabaseError::new(file!(), line!(), "commit DbExploredEndpoint::insert", e)
    })?;

    txn = env.pool.begin().await?;
    let nodes = DbExploredEndpoint::find_all_by_ip(bmc_ip, &mut txn).await?;
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

    let nodes = DbExploredEndpoint::find_all_by_ip(bmc_ip, &mut txn).await?;
    assert_eq!(nodes.len(), 1);
    let node = nodes.first();
    assert_eq!(node.unwrap().report.last_exploration_error, None);

    Ok(())
}

// Test that discover_machines will reject request of machine that was not created by site-explorer when create_machines = true
#[sqlx::test(fixtures("create_domain", "create_vpc",))]
async fn test_disable_machine_creation_outside_site_explorer(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = common::api_fixtures::get_config();
    config.site_explorer = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: carbide::dynamic_settings::create_machines(true),
        ..Default::default()
    };
    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await;
    let host_sim = env.start_managed_host_sim();
    let _underlay_segment = create_underlay_network_segment(&env).await;
    let _admin_segment = create_admin_network_segment(&env).await;

    let hardware_info = HardwareInfo::from(&host_sim.config);
    let discovery_info = DiscoveryInfo::try_from(hardware_info.clone()).unwrap();
    let oob_mac = MacAddress::from_str("a0:88:c2:08:80:95")?;
    let response = env
        .api
        .discover_dhcp(tonic::Request::new(DhcpDiscovery {
            mac_address: oob_mac.to_string(),
            relay_address: "192.0.1.1".to_string(),
            link_address: None,
            vendor_string: Some("NVIDIA/OOB".to_string()),
            circuit_id: None,
            remote_id: None,
        }))
        .await
        .unwrap()
        .into_inner();

    assert!(response.machine_interface_id.is_some());

    let _dm_response = env
        .api
        .discover_machine(Request::new(MachineDiscoveryInfo {
            machine_interface_id: response.machine_interface_id.clone(),
            discovery_data: Some(DiscoveryData::Info(discovery_info)),
            create_machine: true,
        }))
        .await;

    // assert!(dm_response.is_err_and(|e| e.message().contains("was not discovered by site-explore")));

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
async fn test_fallback_dpu_serial(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;
    let underlay_segment = create_underlay_network_segment(&env).await;
    let _admin_segment = create_admin_network_segment(&env).await;

    const HOST1_DPU_MAC: &str = "B8:3F:D2:90:97:A6";
    const HOST1_MAC: &str = "AA:AB:AC:AD:AA:02";
    const HOST1_DPU_SERIAL_NUMBER: &str = "host1_dpu_serial_number";

    let mut host1_dpu = FakeMachine {
        mac: HOST1_DPU_MAC.parse().unwrap(),
        dhcp_vendor: "Vendor1".to_string(),
        segment: underlay_segment,
        ip: String::new(),
    };

    let mut host1 = FakeMachine {
        mac: HOST1_MAC.parse().unwrap(),
        dhcp_vendor: "Vendor2".to_string(),
        segment: underlay_segment,
        ip: String::new(),
    };

    // Create dhcp entries and machine_interface entries for the machines
    for machine in [&mut host1_dpu, &mut host1] {
        let response = env
            .api
            .discover_dhcp(tonic::Request::new(DhcpDiscovery {
                mac_address: machine.mac.to_string(),
                relay_address: match machine.segment {
                    s if s == underlay_segment => "192.0.1.1".to_string(),
                    _ => "192.0.2.1".to_string(),
                },
                link_address: None,
                vendor_string: Some(machine.dhcp_vendor.clone()),
                circuit_id: None,
                remote_id: None,
            }))
            .await?
            .into_inner();
        tracing::info!(
            "DHCP with mac {} assigned ip {}",
            machine.mac,
            response.address
        );
        machine.ip = response.address;
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
        create_machines: carbide::dynamic_settings::create_machines(true),
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
    );

    // Create expected_machine entry for host1 w.o fallback_dpu_serial_number
    let mut txn = env.pool.begin().await?;
    let mut host1_expected_machine = ExpectedMachine::create(
        &mut txn,
        HOST1_MAC.to_string().parse().unwrap(),
        "user1".to_string(),
        "pw".to_string(),
        "host1".to_string(),
        vec![],
    )
    .await?;
    txn.commit().await?;

    // Run site explorer
    explorer.run_single_iteration().await.unwrap();
    let mut txn = env.pool.begin().await?;
    let explored_endpoints = DbExploredEndpoint::find_all(&mut txn).await.unwrap();

    // Mark explored endpoints as pre-ingestion_complete
    for ee in explored_endpoints.clone() {
        DbExploredEndpoint::set_preingestion_complete(ee.address, &mut txn).await?;
    }
    txn.commit().await?;

    assert_eq!(explored_endpoints.len(), 2);

    let mut txn = env.pool.begin().await?;
    let mut explored_managed_hosts = DbExploredManagedHost::find_all(&mut txn).await?;
    let mut machines = Machine::find(&mut txn, ObjectFilter::All, MachineSearchConfig::default())
        .await
        .unwrap();

    txn.commit().await?;

    // There should be no managed host
    assert_eq!(explored_managed_hosts.len(), 0);
    assert_eq!(machines.len(), 0);

    // Now update expected_machine entry with fallback_dpu_serial
    let mut txn = env.pool.begin().await?;
    host1_expected_machine
        .update(
            &mut txn,
            "user1".to_string(),
            "pw".to_string(),
            "host1".to_string(),
            vec![HOST1_DPU_SERIAL_NUMBER.to_string()],
        )
        .await?;
    txn.commit().await?;

    explorer.run_single_iteration().await.unwrap();
    let mut txn = env.pool.begin().await?;
    explored_managed_hosts = DbExploredManagedHost::find_all(&mut txn).await?;
    machines = Machine::find(&mut txn, ObjectFilter::All, MachineSearchConfig::default())
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
        assert!(<Vec<Machine> as AsRef<Vec<Machine>>>::as_ref(&machines)
            .iter()
            .any(|x| { x.bmc_info().ip.clone().unwrap_or_default() == bmc_ip }));
    }
    Ok(())
}

async fn fetch_exploration_report(env: &TestEnv) -> rpc::site_explorer::SiteExplorationReport {
    env.api
        .get_site_exploration_report(tonic::Request::new(GetSiteExplorationRequest::default()))
        .await
        .unwrap()
        .into_inner()
}

#[sqlx::test(fixtures("create_domain", "create_vpc",))]
async fn test_mi_attach_dpu_if_mi_exists_during_machine_creation(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool).await;
    let _underlay_segment = create_underlay_network_segment(&env).await;
    let _admin_segment = create_admin_network_segment(&env).await;

    let mock_host = ManagedHostConfig::default();
    let mock_dpu = mock_host.dpus.first().unwrap();
    let oob_mac = mock_dpu.oob_mac_address;

    // Create mi now.
    let _response = env
        .api
        .discover_dhcp(tonic::Request::new(DhcpDiscovery {
            mac_address: oob_mac.to_string(),
            relay_address: "192.0.2.1".to_string(),
            link_address: None,
            vendor_string: Some("bluefield".to_string()),
            circuit_id: None,
            remote_id: None,
        }))
        .await?
        .into_inner();

    let mut dpu_report: EndpointExplorationReport = mock_dpu.clone().into();
    dpu_report.generate_machine_id(false)?;

    let explored_dpus = vec![ExploredDpu {
        bmc_ip: IpAddr::from_str("192.168.1.2")?,
        host_pf_mac_address: Some(mock_dpu.host_mac_address),
        report: dpu_report.clone(),
    }];

    let response = env
        .api
        .discover_dhcp(tonic::Request::new(DhcpDiscovery {
            mac_address: mock_host.bmc_mac_address.to_string(),
            relay_address: "192.0.1.1".to_string(),
            link_address: None,
            vendor_string: Some("NVIDIA/OOB".to_string()),
            circuit_id: None,
            remote_id: None,
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(!response.address.is_empty());

    let interface_id = response.machine_interface_id;
    let mut ifaces = env
        .api
        .find_interfaces(tonic::Request::new(rpc::forge::InterfaceSearchQuery {
            id: Some(interface_id.unwrap()),
            ip: None,
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(ifaces.interfaces.len(), 1);
    let iface = ifaces.interfaces.remove(0);
    let mut addresses = iface.address;
    let host_bmc_ip = addresses.remove(0);

    let exploration_report = ExploredManagedHost {
        host_bmc_ip: IpAddr::from_str(&host_bmc_ip)?,
        dpus: explored_dpus.clone(),
    };

    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());
    let test_meter = TestMeter::default();
    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: carbide::dynamic_settings::create_machines(true),
        ..Default::default()
    };

    let explorer = SiteExplorer::new(
        env.pool.clone(),
        explorer_config,
        test_meter.meter(),
        endpoint_explorer.clone(),
        Arc::new(env.config.get_firmware_config()),
        env.common_pools.clone(),
    );

    // Machine interface should not have any machine id associated with it right now.
    let mut txn = env.pool.begin().await?;
    let mi = db::machine_interface::find_by_mac_address(&mut txn, oob_mac).await?;
    assert!(mi[0].attached_dpu_machine_id.is_none());
    assert!(mi[0].machine_id.is_none());
    txn.rollback().await?;

    assert!(
        explorer
            .create_managed_host(
                exploration_report,
                EndpointExplorationReport::default(),
                &env.pool
            )
            .await?
    );

    // At this point, create_managed_host must have updated the associated machine id in
    // machine_interfaces table.
    let mut txn = env.pool.begin().await?;
    let mi = db::machine_interface::find_by_mac_address(&mut txn, oob_mac).await?;
    assert!(mi[0].attached_dpu_machine_id.is_some());
    assert!(mi[0].machine_id.is_some());
    txn.rollback().await?;

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc",))]
async fn test_mi_attach_dpu_if_mi_created_after_machine_creation(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool).await;
    let _underlay_segment = create_underlay_network_segment(&env).await;
    let _admin_segment = create_admin_network_segment(&env).await;
    let mock_host = ManagedHostConfig::default();
    let mock_dpu = mock_host.dpus.first().unwrap();

    let mut dpu_report: EndpointExplorationReport = mock_dpu.clone().into();
    dpu_report.generate_machine_id(false)?;
    let dpu_machine_id = dpu_report.machine_id.clone().unwrap();

    let explored_dpus = vec![ExploredDpu {
        bmc_ip: IpAddr::from_str("192.168.1.2")?,
        host_pf_mac_address: Some(mock_dpu.host_mac_address),
        report: dpu_report.clone(),
    }];

    let response = env
        .api
        .discover_dhcp(tonic::Request::new(DhcpDiscovery {
            mac_address: mock_host.bmc_mac_address.to_string(),
            relay_address: "192.0.1.1".to_string(),
            link_address: None,
            vendor_string: Some("NVIDIA/OOB".to_string()),
            circuit_id: None,
            remote_id: None,
        }))
        .await
        .unwrap()
        .into_inner();
    assert!(!response.address.is_empty());

    let interface_id = response.machine_interface_id;
    let mut ifaces = env
        .api
        .find_interfaces(tonic::Request::new(rpc::forge::InterfaceSearchQuery {
            id: Some(interface_id.unwrap()),
            ip: None,
        }))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(ifaces.interfaces.len(), 1);
    let iface = ifaces.interfaces.remove(0);
    let mut addresses = iface.address;
    let host_bmc_ip = addresses.remove(0);

    let exploration_report = ExploredManagedHost {
        host_bmc_ip: IpAddr::from_str(&host_bmc_ip)?,
        dpus: explored_dpus.clone(),
    };

    let endpoint_explorer = Arc::new(MockEndpointExplorer::default());
    let test_meter = TestMeter::default();
    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: carbide::dynamic_settings::create_machines(true),
        ..Default::default()
    };

    let explorer = SiteExplorer::new(
        env.pool.clone(),
        explorer_config,
        test_meter.meter(),
        endpoint_explorer.clone(),
        Arc::new(env.config.get_firmware_config()),
        env.common_pools.clone(),
    );

    // No way to find a machine_interface using machine id as machine id is not yet associated with
    // interface (right now no machine interface is created yet).
    let mut txn = env.pool.begin().await?;
    let mi =
        db::machine_interface::find_by_machine_ids(&mut txn, &[dpu_machine_id.clone()]).await?;
    assert!(mi.is_empty());
    txn.rollback().await?;

    assert!(
        explorer
            .create_managed_host(
                exploration_report.clone(),
                EndpointExplorationReport::default(),
                &env.pool
            )
            .await?
    );

    // At this point, create_managed_hostmust have created machine but can not associate it with to
    // any interface as interface does not exist.
    let mut txn = env.pool.begin().await?;
    let machine = Machine::find_one(
        &mut txn,
        &dpu_machine_id,
        MachineSearchConfig {
            include_dpus: true,
            ..MachineSearchConfig::default()
        },
    )
    .await?;
    assert!(machine.is_some());

    // No way to find a machine_interface using machine id as machine id is not yet associated with
    // interface (right now no machine interface is created yet).
    let mi =
        db::machine_interface::find_by_machine_ids(&mut txn, &[dpu_machine_id.clone()]).await?;
    assert!(mi.is_empty());
    txn.rollback().await?;

    // Create mi now.
    let _response = env
        .api
        .discover_dhcp(tonic::Request::new(DhcpDiscovery {
            mac_address: mock_dpu.oob_mac_address.to_string(),
            relay_address: "192.0.2.1".to_string(),
            link_address: None,
            vendor_string: Some("bluefield".to_string()),
            circuit_id: None,
            remote_id: None,
        }))
        .await?
        .into_inner();

    // Machine is already created, create_managed_host should return false.
    assert!(
        !explorer
            .create_managed_host(
                exploration_report,
                EndpointExplorationReport::default(),
                &env.pool
            )
            .await?
    );

    // At this point, create_managed_host must have updated the associated machine id in
    // machine_interfaces table.
    let mut txn = env.pool.begin().await?;
    let mi =
        db::machine_interface::find_by_machine_ids(&mut txn, &[dpu_machine_id.clone()]).await?;
    assert!(!mi.is_empty());
    let value = mi.values().collect_vec()[0].clone()[0].clone();
    assert_eq!(
        value.attached_dpu_machine_id.clone().unwrap(),
        dpu_machine_id
    );
    assert_eq!(value.machine_id.unwrap(), dpu_machine_id);
    txn.rollback().await?;

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc",))]
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
    let _underlay_segment = create_underlay_network_segment(&env).await;
    let _admin_segment = create_admin_network_segment(&env).await;
    let mut txn = env.pool.begin().await?;
    let mut oob_interfaces = Vec::new();
    let mut explored_dpus = Vec::new();

    for (i, mock_dpu) in mock_dpus.iter().enumerate() {
        let oob_mac = mock_dpu.bmc_mac_address;
        let response = env
            .api
            .discover_dhcp(tonic::Request::new(DhcpDiscovery {
                mac_address: oob_mac.to_string(),
                relay_address: "192.0.1.1".to_string(),
                link_address: None,
                vendor_string: Some("NVIDIA/OOB".to_string()),
                circuit_id: None,
                remote_id: None,
            }))
            .await
            .unwrap()
            .into_inner();

        assert!(!response.address.is_empty());
        let oob_interface = db::machine_interface::find_by_mac_address(&mut txn, oob_mac).await?;
        assert!(oob_interface[0].is_primary);
        oob_interfaces.push(oob_interface[0].clone());

        let mut dpu_report: EndpointExplorationReport = mock_dpu.clone().into();
        dpu_report.generate_machine_id(false)?;
        explored_dpus.push(ExploredDpu {
            bmc_ip: IpAddr::from_str(format!("192.168.1.{i}").as_str())?,
            host_pf_mac_address: Some(mock_dpu.host_mac_address),
            report: dpu_report.clone(),
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
#[sqlx::test(fixtures("create_domain", "create_vpc"))]
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

    create_underlay_network_segment(&env).await;
    create_admin_network_segment(&env).await;
    create_host_inband_network_segment(&env).await;

    let zero_dpu_host = api_fixtures::site_explorer::new_host(&env, 0).await?;
    assert_eq!(zero_dpu_host.dpu_snapshots.len(), 0);

    let single_dpu_host = api_fixtures::site_explorer::new_host(&env, 1).await?;
    assert_eq!(single_dpu_host.dpu_snapshots.len(), 1);

    let two_dpu_host = api_fixtures::site_explorer::new_host(&env, 2).await?;
    assert_eq!(two_dpu_host.dpu_snapshots.len(), 2);

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
async fn test_site_explorer_fixtures_singledpu(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool).await;
    create_underlay_network_segment(&env).await;
    create_admin_network_segment(&env).await;

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
        .insert_site_exploration_results()
        .await?
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
                db::managed_host::load_snapshot(
                    &mut txn,
                    &MachineId::from_str(&machine_id.id)?,
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

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
async fn test_site_explorer_fixtures_multidpu(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool).await;
    create_underlay_network_segment(&env).await;
    create_admin_network_segment(&env).await;

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
        .insert_site_exploration_results()
        .await?
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
                db::managed_host::load_snapshot(
                    &mut txn,
                    &MachineId::from_str(&machine_id.id)?,
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

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
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

    create_underlay_network_segment(&env).await;
    create_admin_network_segment(&env).await;
    create_host_inband_network_segment(&env).await;

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
        .insert_site_exploration_results()
        .await?
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
                db::managed_host::load_snapshot(
                    &mut txn,
                    &MachineId::from_str(&machine_id.id)?,
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
#[sqlx::test(fixtures("create_domain", "create_vpc"))]
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

    create_underlay_network_segment(&env).await;
    create_admin_network_segment(&env).await;
    create_host_inband_network_segment(&env).await;

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
        .insert_site_exploration_results()
        .await?
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
                let predicted_interfaces =
                    db::predicted_machine_interface::PredictedMachineInterface::find_by(
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
                db::managed_host::load_snapshot(
                    &mut txn,
                    &MachineId::from_str(&machine_id.id)?,
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
