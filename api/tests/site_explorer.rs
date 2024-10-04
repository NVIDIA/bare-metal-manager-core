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

use std::{
    collections::HashMap,
    net::IpAddr,
    net::SocketAddr,
    str::FromStr,
    sync::{Arc, Mutex},
};

use carbide::{
    cfg::SiteExplorerConfig,
    db::{
        self,
        expected_machine::ExpectedMachine,
        explored_endpoints::DbExploredEndpoint,
        machine::{Machine, MachineSearchConfig},
        machine_topology::MachineTopology,
        DatabaseError,
    },
    model::{
        machine::{DpuDiscoveringState, DpuInitState, MachineInterfaceSnapshot, ManagedHostState},
        site_explorer::{
            Chassis, ComputerSystem, ComputerSystemAttributes, EndpointExplorationError,
            EndpointExplorationReport, EndpointType, EthernetInterface, ExploredDpu,
            ExploredManagedHost, Inventory, Manager, NetworkAdapter, NicMode, Service,
        },
    },
    resource_pool::ResourcePoolStats,
    site_explorer::{EndpointExplorer, SiteExplorationMetrics, SiteExplorer},
    state_controller::machine::handler::MachineStateHandlerBuilder,
    CarbideError,
};
use carbide::{db::explored_managed_host::DbExploredManagedHost, model::site_explorer::PowerState};
use carbide::{db::ObjectFilter, model::site_explorer::UefiDevicePath};
use common::api_fixtures::TestEnv;
use forge_uuid::{machine::MachineId, network::NetworkSegmentId};
use itertools::Itertools;
use mac_address::MacAddress;
use rpc::{
    forge::{forge_server::Forge, DhcpDiscovery, GetSiteExplorationRequest},
    site_explorer::ExploredDpu as RpcExploredDpu,
    site_explorer::ExploredManagedHost as RpcExploredManagedHost,
    BlockDevice, DiscoveryData, DiscoveryInfo, MachineDiscoveryInfo,
};
use tonic::Request;

use crate::common::{
    api_fixtures::{
        dpu::create_dpu_hardware_info,
        network_segment::{create_admin_network_segment, create_underlay_network_segment},
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

    let endpoint_explorer = Arc::new(FakeEndpointExplorer {
        reports: Arc::new(Mutex::new(HashMap::new())),
    });

    {
        let mut guard = endpoint_explorer.reports.lock().unwrap();
        guard.insert(
            machines[0].ip.parse().unwrap(),
            Ok(EndpointExplorationReport {
                endpoint_type: EndpointType::Bmc,
                last_exploration_error: None,
                vendor: Some(bmc_vendor::BMCVendor::Nvidia),
                machine_id: None,
                managers: vec![Manager {
                    id: "bmc".to_string(),
                    ethernet_interfaces: vec![EthernetInterface {
                        id: Some("eth0".to_string()),
                        description: Some("Management Network Interface".to_string()),
                        interface_enabled: Some(true),
                        mac_address: Some("b8:3f:d2:90:97:a6".parse().unwrap()),
                        uefi_device_path: None,
                    }],
                }],
                systems: vec![ComputerSystem {
                    id: "Bluefield".to_string(),
                    ethernet_interfaces: Vec::new(),
                    manufacturer: None,
                    model: None,
                    serial_number: Some("MT2333XZ0X5W".to_string()),
                    attributes: ComputerSystemAttributes {
                        nic_mode: Some(NicMode::Dpu),
                        http_dev1_interface: None,
                    },
                    pcie_devices: vec![],
                    base_mac: Some("B83FD29097A4".to_string()),
                    power_state: PowerState::On,
                }],
                chassis: vec![Chassis {
                    id: "Card1".to_string(),
                    manufacturer: Some("Nvidia".to_string()),
                    model: Some("Bluefield 3 SmartNIC Main Card".to_string()),
                    part_number: Some("900-9D3B6-00CV-AA0".to_string()),
                    serial_number: Some("MT2333XZ0X5W".to_string()),
                    network_adapters: vec![],
                }],
                service: vec![Service {
                    id: "FirmwareInventory".to_string(),
                    inventories: vec![
                        Inventory {
                            id: "DPU_NIC".to_string(),
                            description: Some("Host image".to_string()),
                            version: Some("32.38.1002".to_string()),
                            release_date: None,
                        },
                        Inventory {
                            id: "DPU_BSP".to_string(),
                            description: Some("Host image".to_string()),
                            version: Some("4.5.0.12984".to_string()),
                            release_date: None,
                        },
                        Inventory {
                            id: "BMC_Firmware".to_string(),
                            description: Some("Host image".to_string()),
                            version: Some("BF-23.10-3".to_string()),
                            release_date: None,
                        },
                        Inventory {
                            id: "DPU_OFED".to_string(),
                            description: Some("Host image".to_string()),
                            version: Some("MLNX_OFED_LINUX-23.10-1.1.8".to_string()),
                            release_date: None,
                        },
                        Inventory {
                            id: "DPU_OS".to_string(),
                            description: Some("Host image".to_string()),
                            version: Some(
                                "DOCA_2.5.0_BSP_4.5.0_Ubuntu_22.04-1.20231129.prod".to_string(),
                            ),
                            release_date: None,
                        },
                        Inventory {
                            id: "DPU_SYS_IMAGE".to_string(),
                            description: Some("Host image".to_string()),
                            version: Some("b83f:d203:0090:97a4".to_string()),
                            release_date: None,
                        },
                    ],
                }],
                versions: HashMap::default(),
                model: None,
            }),
        );
        guard.insert(
            machines[1].ip.parse().unwrap(),
            Err(EndpointExplorationError::Unauthorized {
                details: "Not authorized".to_string(),
            }),
        );
        guard.insert(
            machines[2].ip.parse().unwrap(),
            Ok(EndpointExplorationReport {
                endpoint_type: EndpointType::Bmc,
                last_exploration_error: None,
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
        );
    }

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
    {
        let mut guard = endpoint_explorer.reports.lock().unwrap();
        let m0 = guard.get_mut(&machines[0].ip.parse().unwrap()).unwrap();
        *m0 = Err(EndpointExplorationError::Unreachable {
            details: Some("test_unreachable_detail".to_string()),
        });

        let m1 = guard.get_mut(&machines[1].ip.parse().unwrap()).unwrap();
        *m1 = Ok(EndpointExplorationReport {
            endpoint_type: EndpointType::Bmc,
            last_exploration_error: None,
            vendor: Some(bmc_vendor::BMCVendor::Dell),
            managers: vec![Manager {
                id: "iDRAC.Embedded.1".to_string(),
                ethernet_interfaces: vec![EthernetInterface {
                    id: Some("NIC.1".to_string()),
                    description: Some("Management Network Interface".to_string()),
                    interface_enabled: Some(true),
                    mac_address: Some("c8:4b:d6:7a:dc:bc".parse().unwrap()),
                    uefi_device_path: None,
                }],
            }],
            systems: vec![ComputerSystem {
                id: "System.Embedded.1".to_string(),
                manufacturer: Some("Dell Inc.".to_string()),
                model: Some("PowerEdge R750".to_string()),
                serial_number: Some("MXFC40025U031S".to_string()),
                ethernet_interfaces: vec![
                    EthernetInterface {
                        id: Some("NIC.Embedded.2-1-1".to_string()),
                        description: Some("Embedded NIC 1 Port 2 Partition 1".to_string()),
                        interface_enabled: Some(true),
                        mac_address: Some("c8:4b:d6:7b:ab:93".parse().unwrap()),
                        uefi_device_path: None,
                    },
                    EthernetInterface {
                        id: Some("NIC.Embedded.1-1-1".to_string()),
                        description: Some("Embedded NIC 1 Port 1 Partition 1".to_string()),
                        interface_enabled: Some(false),
                        mac_address: Some("c8:4b:d6:7b:ab:92".parse().unwrap()),
                        uefi_device_path: None,
                    },
                    EthernetInterface {
                        id: Some("NIC.Slot.5-1".to_string()),
                        description: Some("NIC in Slot 5 Port 1".to_string()),
                        interface_enabled: Some(true),
                        mac_address: Some("b8:3f:d2:90:97:a4".parse().unwrap()),
                        uefi_device_path: None,
                    },
                ],
                attributes: ComputerSystemAttributes::default(),
                pcie_devices: vec![],
                base_mac: None,
                power_state: PowerState::On,
            }],
            chassis: vec![Chassis {
                id: "System.Embedded.1".to_string(),
                manufacturer: Some("Dell Inc.".to_string()),
                model: Some("PowerEdge R750".to_string()),
                part_number: Some("SB27A42862".to_string()),
                serial_number: Some("MXFC40025U031S".to_string()),
                network_adapters: vec![
                    NetworkAdapter {
                        id: "slot-1".to_string(),
                        manufacturer: Some("MLNX".to_string()),
                        model: Some("BlueField-3 P-Series DPU 200GbE/".to_string()),
                        part_number: Some("900-9D3B6-00CV-A".to_string()),
                        serial_number: Some("MT2333XZ0X5W".to_string()),
                    },
                    NetworkAdapter {
                        id: "slot-2".to_string(),
                        manufacturer: Some("Broadcom Limited".to_string()),
                        model: Some("5720".to_string()),
                        part_number: Some("SN30L21970".to_string()),
                        serial_number: Some("L2NV97J018G".to_string()),
                    },
                ],
            }],
            service: vec![Service {
                id: "FirmwareInventory".to_string(),
                inventories: vec![
                    Inventory {
                        id: "Slot_3.1".to_string(),
                        description: Some("The information of Firmware firmware.".to_string()),
                        version: Some("32.38.1002".to_string()),
                        release_date: None,
                    },
                    Inventory {
                        id: "Installed-25227-6.00.30.00__iDRAC.Embedded.1-1".to_string(),
                        description: Some("The information of BMC (Primary) firmware.".to_string()),
                        version: Some("6.00.30.00".to_string()),
                        release_date: Some("2023-09-12T00:00:00Z".to_string()),
                    },
                    Inventory {
                        id: "Current-159-1.6.5__BIOS.Setup.1-1".to_string(),
                        description: Some("Currently running BIOS firmware.".to_string()),
                        version: Some("1.6.5".to_string()),
                        release_date: Some("2023-09-12T00:00:00Z".to_string()),
                    },
                    Inventory {
                        id: "Installed-159-1.6.5__BIOS.Setup.1-1".to_string(),
                        description: Some("Currently running BIOS firmware.".to_string()),
                        version: Some("1.6.5".to_string()),
                        release_date: Some("2023-09-12T00:00:00Z".to_string()),
                    },
                    Inventory {
                        id: "Installed-110428-00.1D.9C__PSU.Slot.1".to_string(),
                        description: Some("Some other firmware.".to_string()),
                        version: Some("00.1D.9C".to_string()),
                        release_date: Some("2023-09-12T00:00:00Z".to_string()),
                    },
                ],
            }],
            machine_id: None, // Only DPU reports have a machine ID listed
            versions: HashMap::default(),
            model: None,
        });
    }

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
            host_pf_mac_address: Some("B8:3F:D2:90:97:A4".to_string()),
            dpus: vec![RpcExploredDpu {
                bmc_ip: machines[0].ip.clone(),
                host_pf_mac_address: Some("B8:3F:D2:90:97:A4".to_string()),
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

    let endpoint_explorer = Arc::new(FakeEndpointExplorer {
        reports: Arc::new(Mutex::new(HashMap::new())),
    });

    {
        let mut guard = endpoint_explorer.reports.lock().unwrap();
        guard.insert(
            machines[0].ip.parse().unwrap(),
            Ok(EndpointExplorationReport {
                endpoint_type: EndpointType::Bmc,
                last_exploration_error: None,
                vendor: Some(bmc_vendor::BMCVendor::Nvidia),
                machine_id: None,
                model: Some("Bluefield 3 SmartNIC Main Card".to_string()),
                managers: vec![Manager {
                    id: "bmc".to_string(),
                    ethernet_interfaces: vec![EthernetInterface {
                        id: Some("eth0".to_string()),
                        description: Some("Management Network Interface".to_string()),
                        interface_enabled: Some(true),
                        mac_address: Some("5a:5b:5c:5d:5e:5f".parse().unwrap()),
                        uefi_device_path: None,
                    }],
                }],
                systems: vec![ComputerSystem {
                    id: "Bluefield".to_string(),
                    ethernet_interfaces: Vec::new(),
                    base_mac: Some("5a:5b:5c:5d:5e:5d".to_string()),
                    manufacturer: None,
                    model: None,
                    serial_number: Some("VVG121GL".to_string()),
                    attributes: ComputerSystemAttributes {
                        nic_mode: Some(NicMode::Dpu),
                        http_dev1_interface: None,
                    },
                    pcie_devices: vec![],
                    power_state: PowerState::On,
                }],
                chassis: vec![Chassis {
                    id: "Card1".to_string(),
                    manufacturer: Some("Nvidia".to_string()),
                    model: Some("Bluefield 3 SmartNIC Main Card".to_string()),
                    part_number: Some("900-9D3B6-00CV-AA0".to_string()),
                    serial_number: Some("VVG121GL".to_string()),
                    network_adapters: vec![],
                }],
                service: vec![Service {
                    id: "FirmwareInventory".to_string(),
                    inventories: vec![
                        Inventory {
                            id: "DPU_NIC".to_string(),
                            description: Some("Host image".to_string()),
                            version: Some("32.38.1002".to_string()),
                            release_date: None,
                        },
                        Inventory {
                            id: "BMC_Firmware".to_string(),
                            description: Some("Host image".to_string()),
                            version: Some("BF-23.10-3".to_string()),
                            release_date: None,
                        },
                    ],
                }],
                versions: HashMap::default(),
            }),
        );
        guard.insert(
            machines[1].ip.parse().unwrap(),
            Ok(EndpointExplorationReport {
                endpoint_type: EndpointType::Bmc,
                // Pretend there was previously a successful exploration
                // but now something has gone wrong.
                last_exploration_error: Some(EndpointExplorationError::Unauthorized {
                    details: "Not authorized".to_string(),
                }),
                vendor: Some(bmc_vendor::BMCVendor::Lenovo),
                machine_id: None,
                model: None,
                managers: Vec::new(),
                systems: Vec::new(),
                chassis: Vec::new(),
                service: Vec::new(),
                versions: HashMap::default(),
            }),
        );
        guard.insert(
            machines[2].ip.parse().unwrap(),
            Ok(EndpointExplorationReport {
                endpoint_type: EndpointType::Bmc,
                // Pretend there was previously a successful exploration
                // but now something has gone wrong.
                last_exploration_error: Some(EndpointExplorationError::MissingCredentials {
                    key: "some_cred".to_string(),
                    cause: "it's not there!".to_string(),
                }),
                vendor: Some(bmc_vendor::BMCVendor::Lenovo),
                machine_id: None,
                model: None,
                managers: Vec::new(),
                systems: Vec::new(),
                chassis: Vec::new(),
                service: Vec::new(),
                versions: HashMap::default(),
            }),
        );
        guard.insert(
            machines[3].ip.parse().unwrap(),
            Ok(EndpointExplorationReport {
                endpoint_type: EndpointType::Bmc,
                last_exploration_error: None,
                vendor: Some(bmc_vendor::BMCVendor::Lenovo),
                machine_id: None,
                model: None,
                managers: Vec::new(),
                systems: Vec::new(),
                chassis: Vec::new(),
                service: Vec::new(),
                versions: HashMap::default(),
            }),
        );
        guard.insert(
            machines[4].ip.parse().unwrap(),
            Ok(EndpointExplorationReport {
                endpoint_type: EndpointType::Bmc,
                last_exploration_error: None,
                vendor: Some(bmc_vendor::BMCVendor::Dell),
                managers: vec![Manager {
                    id: "iDRAC.Embedded.1".to_string(),
                    ethernet_interfaces: vec![EthernetInterface {
                        id: Some("NIC.1".to_string()),
                        description: Some("Management Network Interface".to_string()),
                        interface_enabled: Some(true),
                        mac_address: Some(machines[4].mac),
                        uefi_device_path: None,
                    }],
                }],
                systems: vec![ComputerSystem {
                    id: "System.Embedded.1".to_string(),
                    manufacturer: Some("Dell Inc.".to_string()),
                    model: Some("PowerEdge R750".to_string()),
                    serial_number: Some("VVG121GJ".to_string()),
                    base_mac: Some("c8:4b:d6:7b:ab:91".to_string()),
                    ethernet_interfaces: vec![
                        EthernetInterface {
                            id: Some("NIC.Embedded.2-1-1".to_string()),
                            description: Some("Embedded NIC 1 Port 2 Partition 1".to_string()),
                            interface_enabled: Some(true),
                            mac_address: Some("c8:4b:d6:7b:ab:93".parse().unwrap()),
                            uefi_device_path: None,
                        },
                        EthernetInterface {
                            id: Some("NIC.Embedded.1-1-1".to_string()),
                            description: Some("Embedded NIC 1 Port 1 Partition 1".to_string()),
                            interface_enabled: Some(false),
                            mac_address: Some("c8:4b:d6:7b:ab:92".parse().unwrap()),
                            uefi_device_path: None,
                        },
                        EthernetInterface {
                            id: Some("NIC.Slot.5-1".to_string()),
                            description: Some("NIC in Slot 5 Port 1".to_string()),
                            interface_enabled: Some(true),
                            mac_address: Some("b8:3f:d2:90:97:a4".parse().unwrap()),
                            uefi_device_path: None,
                        },
                    ],
                    attributes: ComputerSystemAttributes::default(),
                    pcie_devices: vec![],
                    power_state: PowerState::On,
                }],
                chassis: vec![Chassis {
                    id: "System.Embedded.1".to_string(),
                    manufacturer: Some("Dell Inc.".to_string()),
                    model: Some("PowerEdge R750".to_string()),
                    part_number: Some("SB27A42862".to_string()),
                    serial_number: Some("VVG121GJ".to_string()),
                    network_adapters: vec![
                        NetworkAdapter {
                            id: "slot-1".to_string(),
                            manufacturer: Some("MLNX".to_string()),
                            model: Some("BlueField-3 P-Series DPU 200GbE/".to_string()),
                            part_number: Some("900-9D3B6-00CV-A".to_string()),
                            serial_number: Some("MT2333XZ0X5W".to_string()),
                        },
                        NetworkAdapter {
                            id: "slot-2".to_string(),
                            manufacturer: Some("Broadcom Limited".to_string()),
                            model: Some("5720".to_string()),
                            part_number: Some("SN30L21970".to_string()),
                            serial_number: Some("L2NV97J018G".to_string()),
                        },
                    ],
                }],
                service: vec![Service {
                    id: "FirmwareInventory".to_string(),
                    inventories: vec![
                        Inventory {
                            id: "Slot_3.1".to_string(),
                            description: Some("The information of Firmware firmware.".to_string()),
                            version: Some("32.38.1002".to_string()),
                            release_date: None,
                        },
                        Inventory {
                            id: "Installed-25227-6.00.30.00__iDRAC.Embedded.1-1".to_string(),
                            description: Some(
                                "The information of BMC (Primary) firmware.".to_string(),
                            ),
                            version: Some("6.00.30.00".to_string()),
                            release_date: Some("2023-09-12T00:00:00Z".to_string()),
                        },
                        Inventory {
                            id: "Current-159-1.6.5__BIOS.Setup.1-1".to_string(),
                            description: Some("Currently running BIOS firmware.".to_string()),
                            version: Some("1.6.5".to_string()),
                            release_date: Some("2023-09-12T00:00:00Z".to_string()),
                        },
                        Inventory {
                            id: "Installed-159-1.6.5__BIOS.Setup.1-1".to_string(),
                            description: Some("Currently running BIOS firmware.".to_string()),
                            version: Some("1.6.5".to_string()),
                            release_date: Some("2023-09-12T00:00:00Z".to_string()),
                        },
                        Inventory {
                            id: "Installed-110428-00.1D.9C__PSU.Slot.1".to_string(),
                            description: Some("Some other firmware.".to_string()),
                            version: Some("00.1D.9C".to_string()),
                            release_date: Some("2023-09-12T00:00:00Z".to_string()),
                        },
                    ],
                }],
                machine_id: None, // Only DPU reports have a machine ID listed
                versions: HashMap::default(),
                model: None,
            }),
        );

        guard.insert(
            machines[5].ip.parse().unwrap(),
            Ok(EndpointExplorationReport {
                endpoint_type: EndpointType::Bmc,
                last_exploration_error: None,
                vendor: Some(bmc_vendor::BMCVendor::Lenovo),
                machine_id: None,
                model: None,
                managers: Vec::new(),
                systems: Vec::new(),
                chassis: Vec::new(),
                service: Vec::new(),
                versions: HashMap::default(),
            }),
        );
        guard.insert(
            machines[6].ip.parse().unwrap(),
            Ok(EndpointExplorationReport {
                endpoint_type: EndpointType::Bmc,
                last_exploration_error: None,
                vendor: Some(bmc_vendor::BMCVendor::Nvidia),
                machine_id: None,
                model: Some("Bluefield 3 SmartNIC Main Card".to_string()),
                managers: vec![Manager {
                    id: "bmc".to_string(),
                    ethernet_interfaces: vec![EthernetInterface {
                        id: Some("eth0".to_string()),
                        description: Some("Management Network Interface".to_string()),
                        interface_enabled: Some(true),
                        mac_address: Some("ef:cd:ab:ef:cd:ab".parse().unwrap()),
                        uefi_device_path: None,
                    }],
                }],
                systems: vec![ComputerSystem {
                    id: "Bluefield".to_string(),
                    ethernet_interfaces: Vec::new(),
                    base_mac: Some("c8:4b:d6:7b:ab:91".to_string()),
                    manufacturer: None,
                    model: None,
                    serial_number: Some("MT2333XZ0X5W".to_string()),
                    attributes: ComputerSystemAttributes {
                        nic_mode: Some(NicMode::Dpu),
                        http_dev1_interface: None,
                    },
                    pcie_devices: vec![],
                    power_state: PowerState::On,
                }],
                chassis: vec![Chassis {
                    id: "Card1".to_string(),
                    manufacturer: Some("Nvidia".to_string()),
                    model: Some("Bluefield 3 SmartNIC Main Card".to_string()),
                    part_number: Some("900-9D3B6-00CV-AA0".to_string()),
                    serial_number: Some("MT2333XZ0X5W".to_string()),
                    network_adapters: vec![],
                }],
                service: vec![Service {
                    id: "FirmwareInventory".to_string(),
                    inventories: vec![
                        Inventory {
                            id: "DPU_NIC".to_string(),
                            description: Some("Host image".to_string()),
                            version: Some("32.38.1002".to_string()),
                            release_date: None,
                        },
                        Inventory {
                            id: "BMC_Firmware".to_string(),
                            description: Some("Host image".to_string()),
                            version: Some("BF-23.10-3".to_string()),
                            release_date: None,
                        },
                    ],
                }],
                versions: HashMap::default(),
            }),
        );
    }

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
    let env = common::api_fixtures::create_test_env_with_config(pool, Some(config)).await;
    let _underlay_segment = create_underlay_network_segment(&env).await;
    let _admin_segment = create_admin_network_segment(&env).await;

    let endpoint_explorer = Arc::new(FakeEndpointExplorer {
        reports: Arc::new(Mutex::new(HashMap::new())),
    });

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

    let endpoint_explorer = Arc::new(FakeEndpointExplorer {
        reports: Arc::new(Mutex::new(HashMap::new())),
    });

    {
        let mut guard = endpoint_explorer.reports.lock().unwrap();
        guard.insert(
            machines[0].ip.parse().unwrap(),
            Ok(EndpointExplorationReport {
                endpoint_type: EndpointType::Bmc,
                last_exploration_error: None,
                vendor: Some(bmc_vendor::BMCVendor::Nvidia),
                machine_id: None,
                managers: vec![Manager {
                    id: "bmc".to_string(),
                    ethernet_interfaces: vec![EthernetInterface {
                        id: Some("eth0".to_string()),
                        description: Some("Management Network Interface".to_string()),
                        interface_enabled: Some(true),
                        mac_address: Some("b8:3f:d2:90:97:a6".parse().unwrap()),
                        uefi_device_path: None,
                    }],
                }],
                systems: vec![ComputerSystem {
                    id: "Bluefield".to_string(),
                    ethernet_interfaces: Vec::new(),
                    manufacturer: None,
                    model: None,
                    serial_number: Some("MT2333XZ0X5W".to_string()),
                    attributes: ComputerSystemAttributes {
                        nic_mode: Some(NicMode::Dpu),
                        http_dev1_interface: None,
                    },
                    pcie_devices: vec![],
                    base_mac: Some("a088c208804c".to_string()),
                    power_state: PowerState::On,
                }],
                chassis: vec![Chassis {
                    id: "Card1".to_string(),
                    manufacturer: Some("Nvidia".to_string()),
                    model: Some("Bluefield 3 SmartNIC Main Card".to_string()),
                    part_number: Some("900-9D3B6-00CV-AA0".to_string()),
                    serial_number: Some("MT2333XZ0X5W".to_string()),
                    network_adapters: vec![],
                }],
                service: vec![Service {
                    id: "FirmwareInventory".to_string(),
                    inventories: vec![
                        Inventory {
                            id: "DPU_NIC".to_string(),
                            description: Some("Host image".to_string()),
                            version: Some("32.38.1002".to_string()),
                            release_date: None,
                        },
                        Inventory {
                            id: "DPU_BSP".to_string(),
                            description: Some("Host image".to_string()),
                            version: Some("4.5.0.12984".to_string()),
                            release_date: None,
                        },
                        Inventory {
                            id: "BMC_Firmware".to_string(),
                            description: Some("Host image".to_string()),
                            version: Some("BF-23.10-3".to_string()),
                            release_date: None,
                        },
                        Inventory {
                            id: "DPU_OFED".to_string(),
                            description: Some("Host image".to_string()),
                            version: Some("MLNX_OFED_LINUX-23.10-1.1.8".to_string()),
                            release_date: None,
                        },
                        Inventory {
                            id: "DPU_OS".to_string(),
                            description: Some("Host image".to_string()),
                            version: Some(
                                "DOCA_2.5.0_BSP_4.5.0_Ubuntu_22.04-1.20231129.prod".to_string(),
                            ),
                            release_date: None,
                        },
                        Inventory {
                            id: "DPU_SYS_IMAGE".to_string(),
                            description: Some("Host image".to_string()),
                            version: Some("b83f:d203:0090:97a4".to_string()),
                            release_date: None,
                        },
                    ],
                }],
                versions: HashMap::default(),
                model: None,
            }),
        );
        guard.insert(
            machines[1].ip.parse().unwrap(),
            Err(EndpointExplorationError::Unauthorized {
                details: "Not authorized".to_string(),
            }),
        );
    }

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
    let env = common::api_fixtures::create_test_env_with_config(pool, Some(config)).await;
    let _underlay_segment = create_underlay_network_segment(&env).await;
    let _admin_segment = create_admin_network_segment(&env).await;

    let endpoint_explorer = Arc::new(FakeEndpointExplorer {
        reports: Arc::new(Mutex::new(HashMap::new())),
    });

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

    let mut dpu_report = EndpointExplorationReport {
        endpoint_type: EndpointType::Bmc,
        last_exploration_error: None,
        vendor: Some(bmc_vendor::BMCVendor::Nvidia),
        machine_id: None,
        managers: vec![Manager {
            id: "Bluefield_BMC".to_string(),
            ethernet_interfaces: vec![EthernetInterface {
                id: Some("eth0".to_string()),
                description: Some("Management Network Interface".to_string()),
                interface_enabled: Some(true),
                mac_address: Some("a0:88:c2:08:80:97".parse().unwrap()),
                uefi_device_path: None,
            }],
        }],
        systems: vec![ComputerSystem {
            id: "Bluefield".to_string(),
            ethernet_interfaces: vec![EthernetInterface {
                id: Some("oob_net0".to_string()),
                description: Some("1G DPU OOB network interface".to_string()),
                interface_enabled: Some(true),
                mac_address: Some(oob_mac),
                uefi_device_path: None,
            }],
            manufacturer: None,
            model: None,
            serial_number: Some("MT2328XZ185R".to_string()),
            attributes: ComputerSystemAttributes {
                nic_mode: Some(NicMode::Dpu),
                http_dev1_interface: None,
            },
            pcie_devices: vec![],
            base_mac: Some("a088c208804c".to_string()),
            power_state: PowerState::On,
        }],
        chassis: vec![Chassis {
            id: "Card1".to_string(),
            manufacturer: Some("Nvidia".to_string()),
            model: Some("Bluefield 3 SmartNIC Main Card".to_string()),
            part_number: Some("900-9D3B6-00CV-AA0".to_string()),
            serial_number: Some("MT2328XZ185R".to_string()),
            network_adapters: vec![],
        }],
        service: vec![Service {
            id: "FirmwareInventory".to_string(),
            inventories: vec![
                Inventory {
                    id: "DPU_NIC".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("32.38.1002".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "DPU_BSP".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("4.5.0.12984".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "BMC_Firmware".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("BF-23.10-3".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "DPU_OFED".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("MLNX_OFED_LINUX-23.10-1.1.8".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "DPU_OS".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("DOCA_2.5.0_BSP_4.5.0_Ubuntu_22.04-1.20231129.prod".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "DPU_UEFI".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("4.5.0-43-geb17a52".to_string()),
                    release_date: None,
                },
            ],
        }],
        versions: HashMap::default(),
        model: None,
    };
    dpu_report.generate_machine_id(false)?;

    assert!(dpu_report.machine_id.as_ref().is_some());
    assert_eq!(
        dpu_report.machine_id.as_ref().unwrap().to_string(),
        "fm100ds3gfip02lfgleidqoitqgh8d8mdc4a3j2tdncbjrfjtvrrhn2kleg".to_string(),
    );

    let host_bmc_mac = MacAddress::from_str("a0:88:c2:08:81:98")?;
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
        dpus: vec![ExploredDpu {
            bmc_ip: IpAddr::from_str(response.address.as_str())?,
            host_pf_mac_address: Some(MacAddress::from_str("a0:88:c2:08:80:72")?),
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
        "aarch64".to_string()
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
        "MT2328XZ185R".to_string()
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
                    DpuDiscoveringState::DisableSecureBoot { count: 0 },
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

    let endpoint_explorer = Arc::new(FakeEndpointExplorer {
        reports: Arc::new(Mutex::new(HashMap::new())),
    });

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

    for i in 0..NUM_DPUS {
        let oob_mac = MacAddress::from_str(format!("a0:88:c2:08:80:9{i}").as_str())?;
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

        let serial_number = format!("MT2328XZ18{i}R");

        let mut dpu_report = EndpointExplorationReport {
            endpoint_type: EndpointType::Bmc,
            last_exploration_error: None,
            vendor: Some(bmc_vendor::BMCVendor::Nvidia),
            machine_id: None,
            managers: vec![Manager {
                id: "Bluefield_BMC".to_string(),
                ethernet_interfaces: vec![EthernetInterface {
                    id: Some("eth0".to_string()),
                    description: Some("Management Network Interface".to_string()),
                    interface_enabled: Some(true),
                    mac_address: Some(format!("a0:88:c2:08:80:9{}", i).parse().unwrap()),
                    uefi_device_path: Some(
                        UefiDevicePath::from_str(&format!(
                            "PciRoot(0x8)/Pci(0x2,0xa)/Pci(0x0,0x{:x})/MAC(A088C208545C,0x1)",
                            i
                        ))
                        .unwrap(),
                    ),
                }],
            }],
            systems: vec![ComputerSystem {
                id: "Bluefield".to_string(),
                ethernet_interfaces: Vec::new(),
                manufacturer: None,
                model: None,
                serial_number: Some(serial_number.to_string()),
                attributes: ComputerSystemAttributes {
                    nic_mode: Some(NicMode::Dpu),
                    http_dev1_interface: None,
                },
                pcie_devices: vec![],
                base_mac: Some("a088c208804c".to_string()),
                power_state: PowerState::On,
            }],
            chassis: vec![Chassis {
                id: "Card1".to_string(),
                manufacturer: Some("Nvidia".to_string()),
                model: Some("Bluefield 3 SmartNIC Main Card".to_string()),
                part_number: Some(format!("900-9D3B6-00CV-AA{}", i).to_string()),
                serial_number: Some(serial_number.to_string()),
                network_adapters: vec![],
            }],
            service: vec![Service {
                id: "FirmwareInventory".to_string(),
                inventories: vec![
                    Inventory {
                        id: "DPU_NIC".to_string(),
                        description: Some("Host image".to_string()),
                        version: Some("32.38.1002".to_string()),
                        release_date: None,
                    },
                    Inventory {
                        id: "DPU_BSP".to_string(),
                        description: Some("Host image".to_string()),
                        version: Some("4.5.0.12984".to_string()),
                        release_date: None,
                    },
                    Inventory {
                        id: "BMC_Firmware".to_string(),
                        description: Some("Host image".to_string()),
                        version: Some("BF-23.10-3".to_string()),
                        release_date: None,
                    },
                    Inventory {
                        id: "DPU_OFED".to_string(),
                        description: Some("Host image".to_string()),
                        version: Some("MLNX_OFED_LINUX-23.10-1.1.8".to_string()),
                        release_date: None,
                    },
                    Inventory {
                        id: "DPU_OS".to_string(),
                        description: Some("Host image".to_string()),
                        version: Some(
                            "DOCA_2.5.0_BSP_4.5.0_Ubuntu_22.04-1.20231129.prod".to_string(),
                        ),
                        release_date: None,
                    },
                    Inventory {
                        id: "DPU_UEFI".to_string(),
                        description: Some("Host image".to_string()),
                        version: Some("4.5.0-43-geb17a52".to_string()),
                        release_date: None,
                    },
                ],
            }],
            versions: HashMap::default(),
            model: None,
        };
        dpu_report.generate_machine_id(false)?;
        explored_dpus.push(ExploredDpu {
            bmc_ip: IpAddr::from_str(format!("192.168.1.{i}").as_str())?,
            host_pf_mac_address: Some(MacAddress::from_str(
                format!("a0:88:c2:08:80:7{i}").as_str(),
            )?),
            report: dpu_report.clone(),
        })
    }

    let host_bmc_mac = MacAddress::from_str("a0:88:c2:08:81:99")?;
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

    let mut dpu_report1 = EndpointExplorationReport {
        endpoint_type: EndpointType::Bmc,
        last_exploration_error: last_error.clone(),
        vendor: Some(bmc_vendor::BMCVendor::Nvidia),
        machine_id: None,
        managers: vec![Manager {
            id: "Bluefield_BMC".to_string(),
            ethernet_interfaces: vec![EthernetInterface {
                id: Some("eth0".to_string()),
                description: Some("Management Network Interface".to_string()),
                interface_enabled: Some(true),
                mac_address: Some("a0:88:c2:08:80:97".parse().unwrap()),
                uefi_device_path: None,
            }],
        }],
        systems: vec![ComputerSystem {
            id: "Bluefield".to_string(),
            ethernet_interfaces: Vec::new(),
            manufacturer: None,
            model: None,
            serial_number: Some("MT2328XZ185R".to_string()),
            attributes: ComputerSystemAttributes {
                nic_mode: Some(NicMode::Dpu),
                http_dev1_interface: None,
            },
            pcie_devices: vec![],
            base_mac: Some("a088c208804c".to_string()),
            power_state: PowerState::On,
        }],
        chassis: vec![Chassis {
            id: "Card1".to_string(),
            manufacturer: Some("Nvidia".to_string()),
            model: Some("Bluefield 3 SmartNIC Main Card".to_string()),
            part_number: Some("900-9D3B6-00CV-AA0".to_string()),
            serial_number: Some("MT2328XZ185R".to_string()),
            network_adapters: vec![],
        }],
        service: vec![Service {
            id: "FirmwareInventory".to_string(),
            inventories: vec![
                Inventory {
                    id: "DPU_NIC".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("32.38.1002".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "DPU_BSP".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("4.5.0.12984".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "BMC_Firmware".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("BF-23.10-3".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "DPU_OFED".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("MLNX_OFED_LINUX-23.10-1.1.8".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "DPU_OS".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("DOCA_2.5.0_BSP_4.5.0_Ubuntu_22.04-1.20231129.prod".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "DPU_UEFI".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("4.5.0-43-geb17a52".to_string()),
                    release_date: None,
                },
            ],
        }],
        versions: HashMap::default(),
        model: None,
    };
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
    let env = common::api_fixtures::create_test_env_with_config(pool, Some(config)).await;
    let host_sim = env.start_managed_host_sim();
    let _underlay_segment = create_underlay_network_segment(&env).await;
    let _admin_segment = create_admin_network_segment(&env).await;

    let hardware_info = create_dpu_hardware_info(&host_sim.config);
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

    let dpu_exploration_report = EndpointExplorationReport {
        endpoint_type: EndpointType::Bmc,
        last_exploration_error: None,
        vendor: Some(bmc_vendor::BMCVendor::Nvidia),
        machine_id: None,
        managers: vec![Manager {
            id: "bmc".to_string(),
            ethernet_interfaces: vec![EthernetInterface {
                id: Some("eth0".to_string()),
                description: Some("Management Network Interface".to_string()),
                interface_enabled: Some(true),
                mac_address: Some("b8:3f:d2:90:97:a6".parse().unwrap()),
                uefi_device_path: None,
            }],
        }],
        systems: vec![ComputerSystem {
            id: "Bluefield".to_string(),
            ethernet_interfaces: Vec::new(),
            manufacturer: None,
            model: None,
            serial_number: Some("MT2333XZ0X5W".to_string()),
            attributes: ComputerSystemAttributes {
                nic_mode: Some(NicMode::Dpu),
                http_dev1_interface: None,
            },
            pcie_devices: vec![],
            base_mac: Some("a088c208804c".to_string()),
            power_state: PowerState::On,
        }],
        chassis: vec![Chassis {
            id: "Card1".to_string(),
            manufacturer: Some("Nvidia".to_string()),
            model: Some("Bluefield 3 SmartNIC Main Card".to_string()),
            part_number: Some("900-9D3B6-00CV-AA0".to_string()),
            serial_number: Some("MT2333XZ0X5W".to_string()),
            network_adapters: vec![],
        }],
        service: vec![Service {
            id: "FirmwareInventory".to_string(),
            inventories: vec![
                Inventory {
                    id: "DPU_NIC".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("32.38.1002".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "DPU_BSP".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("4.5.0.12984".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "BMC_Firmware".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("BF-23.10-3".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "DPU_OFED".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("MLNX_OFED_LINUX-23.10-1.1.8".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "DPU_OS".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("DOCA_2.5.0_BSP_4.5.0_Ubuntu_22.04-1.20231129.prod".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "DPU_SYS_IMAGE".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("b83f:d203:0090:97a4".to_string()),
                    release_date: None,
                },
            ],
        }],
        versions: Default::default(),
        model: None,
    };

    let host_exploration_report = EndpointExplorationReport {
        endpoint_type: EndpointType::Bmc,
        last_exploration_error: None,
        vendor: Some(bmc_vendor::BMCVendor::Dell),
        managers: vec![Manager {
            id: "iDRAC.Embedded.1".to_string(),
            ethernet_interfaces: vec![EthernetInterface {
                id: Some("NIC.1".to_string()),
                description: Some("Management Network Interface".to_string()),
                interface_enabled: Some(true),
                mac_address: Some("c8:4b:d6:7a:dc:bc".parse().unwrap()),
                uefi_device_path: None,
            }],
        }],
        systems: vec![ComputerSystem {
            id: "System.Embedded.1".to_string(),
            manufacturer: Some("Dell Inc.".to_string()),
            model: Some("PowerEdge R750".to_string()),
            serial_number: Some("MXFC40025U031S".to_string()),
            ethernet_interfaces: vec![
                EthernetInterface {
                    id: Some("NIC.Embedded.2-1-1".to_string()),
                    description: Some("Embedded NIC 1 Port 2 Partition 1".to_string()),
                    interface_enabled: Some(true),
                    mac_address: Some("c8:4b:d6:7b:ab:93".parse().unwrap()),
                    uefi_device_path: None,
                },
                EthernetInterface {
                    id: Some("NIC.Embedded.1-1-1".to_string()),
                    description: Some("Embedded NIC 1 Port 1 Partition 1".to_string()),
                    interface_enabled: Some(false),
                    mac_address: Some("c8:4b:d6:7b:ab:92".parse().unwrap()),
                    uefi_device_path: None,
                },
                EthernetInterface {
                    id: Some("NIC.Slot.5-1".to_string()),
                    description: Some("NIC in Slot 5 Port 1".to_string()),
                    interface_enabled: Some(true),
                    mac_address: Some("b8:3f:d2:90:97:a4".parse().unwrap()),
                    uefi_device_path: None,
                },
            ],
            attributes: ComputerSystemAttributes::default(),
            pcie_devices: vec![],
            base_mac: None,
            power_state: PowerState::On,
        }],
        chassis: vec![Chassis {
            id: "1".to_string(),
            manufacturer: Some("Lenovo".to_string()),
            model: Some("7Z73CTOLWW".to_string()),
            part_number: Some("SB27A42862".to_string()),
            serial_number: Some("J304AYYZ".to_string()),
            network_adapters: vec![
                NetworkAdapter {
                    id: "slot-1".to_string(),
                    manufacturer: Some("MLNX".to_string()),
                    model: Some("BlueField-3 P-Series DPU 200GbE/".to_string()),
                    part_number: Some("900-9D3B6-00CV-A".to_string()),
                    serial_number: None, //Some("MT2333XZ0X5W".to_string()),
                },
                NetworkAdapter {
                    id: "slot-2".to_string(),
                    manufacturer: Some("Broadcom Limited".to_string()),
                    model: Some("5720".to_string()),
                    part_number: Some("SN30L21970".to_string()),
                    serial_number: Some("L2NV97J018G".to_string()),
                },
            ],
        }],
        service: vec![Service {
            id: "FirmwareInventory".to_string(),
            inventories: vec![
                Inventory {
                    id: "Slot_3.1".to_string(),
                    description: Some("The information of Firmware firmware.".to_string()),
                    version: Some("32.38.1002".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "BMC-Primary".to_string(),
                    description: Some("The information of BMC (Primary) firmware.".to_string()),
                    version: Some("38U-3.86".to_string()),
                    release_date: Some("2023-09-12T00:00:00Z".to_string()),
                },
            ],
        }],
        machine_id: None,
        versions: Default::default(),
        model: None,
    };

    let new_dpu_report = |sn: String| -> EndpointExplorationReport {
        let mut ret = dpu_exploration_report.clone();
        assert_eq!(ret.chassis.len(), 1);
        assert_eq!(ret.systems.len(), 1);
        let mut ch = ret.chassis.remove(0);
        ch.serial_number = Some(sn.clone());
        ret.chassis.push(ch);
        assert_eq!(ret.chassis.len(), 1);

        let mut cs = ret.systems.remove(0);
        cs.serial_number = Some(sn);
        ret.systems.push(cs);
        ret
    };

    let new_host_report = |sn: String,
                           nw_adapter_index: Option<usize>,
                           dpu_sn: Option<String>|
     -> EndpointExplorationReport {
        let mut ret = host_exploration_report.clone();
        assert_eq!(ret.chassis.len(), 1);
        assert_eq!(ret.systems.len(), 1);
        let mut ch = ret.chassis.remove(0);
        ch.serial_number = Some(sn.clone());
        // Change  NetWorkAdapter's Serial Number to dpu_sn
        if let Some(adapter_index) = nw_adapter_index {
            assert!(ch.network_adapters.len() > adapter_index);
            let mut na = ch.network_adapters.remove(adapter_index);
            na.serial_number = dpu_sn;
            ch.network_adapters.insert(adapter_index, na);
        }
        ret.chassis.push(ch);
        assert_eq!(ret.chassis.len(), 1);
        let mut cs = ret.systems.remove(0);
        cs.serial_number = Some(sn);
        ret.systems.push(cs);
        ret
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
    let endpoint_explorer = Arc::new(FakeEndpointExplorer {
        reports: Arc::new(Mutex::new(HashMap::new())),
    });

    // Create a host and dpu reports && host has no dpu_serial
    {
        let mut guard = endpoint_explorer.reports.lock().unwrap();
        guard.insert(
            host1_dpu.ip.parse().unwrap(),
            Ok(new_dpu_report(HOST1_DPU_SERIAL_NUMBER.to_string())),
        );
        guard.insert(
            host1.ip.parse().unwrap(),
            Ok(new_host_report("host1".to_string(), None, None)),
        );
    }

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
        endpoint_explorer.clone(),
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
    return Ok(());
}

/// EndpointExplorer which returns predefined data
struct FakeEndpointExplorer {
    reports:
        Arc<Mutex<HashMap<IpAddr, Result<EndpointExplorationReport, EndpointExplorationError>>>>,
}

#[async_trait::async_trait]
impl EndpointExplorer for FakeEndpointExplorer {
    async fn check_preconditions(
        &self,
        _metrics: &mut SiteExplorationMetrics,
    ) -> Result<(), EndpointExplorationError> {
        Ok(())
    }
    async fn explore_endpoint(
        &self,
        bmc_ip_address: SocketAddr,
        _interface: &MachineInterfaceSnapshot,
        _expected: Option<ExpectedMachine>,
        _last_report: Option<&EndpointExplorationReport>,
    ) -> Result<EndpointExplorationReport, EndpointExplorationError> {
        tracing::info!("Endpoint {bmc_ip_address} is getting explored");
        let guard = self.reports.lock().unwrap();
        let res = guard.get(&bmc_ip_address.ip()).unwrap();
        res.clone()
    }

    async fn redfish_reset_bmc(
        &self,
        _address: SocketAddr,
        _interface: &MachineInterfaceSnapshot,
    ) -> Result<(), EndpointExplorationError> {
        Ok(())
    }

    async fn ipmitool_reset_bmc(
        &self,
        _address: SocketAddr,
        _interface: &MachineInterfaceSnapshot,
    ) -> Result<(), EndpointExplorationError> {
        Ok(())
    }

    async fn redfish_power_control(
        &self,
        _address: SocketAddr,
        _interface: &MachineInterfaceSnapshot,
        _action: libredfish::SystemPowerControl,
    ) -> Result<(), EndpointExplorationError> {
        Ok(())
    }

    async fn have_credentials(&self, _interface: &MachineInterfaceSnapshot) -> bool {
        true
    }

    async fn forge_setup(
        &self,
        _address: SocketAddr,
        _interface: &MachineInterfaceSnapshot,
    ) -> Result<(), EndpointExplorationError> {
        Ok(())
    }

    async fn forge_setup_status(
        &self,
        _address: SocketAddr,
        _interface: &MachineInterfaceSnapshot,
    ) -> Result<libredfish::ForgeSetupStatus, EndpointExplorationError> {
        let setup_status = libredfish::ForgeSetupStatus {
            is_done: true,
            diffs: vec![],
        };
        let res = Ok(setup_status);
        return res;
    }
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
    let oob_mac: MacAddress = "b8:3f:d2:90:97:a6".parse().unwrap();

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

    let serial_number = "MT2328XZ180R".to_string();

    let mut dpu_report = EndpointExplorationReport {
        endpoint_type: EndpointType::Bmc,
        last_exploration_error: None,
        vendor: Some(bmc_vendor::BMCVendor::Nvidia),
        machine_id: None,
        managers: vec![Manager {
            id: "Bluefield_BMC".to_string(),
            ethernet_interfaces: vec![EthernetInterface {
                id: Some("eth0".to_string()),
                description: Some("Management Network Interface".to_string()),
                interface_enabled: Some(true),
                mac_address: Some("a0:88:c2:08:80:90".parse().unwrap()),
                uefi_device_path: None,
            }],
        }],
        systems: vec![ComputerSystem {
            id: "Bluefield".to_string(),
            ethernet_interfaces: vec![EthernetInterface {
                id: Some("oob_net0".to_string()),
                description: Some("1G DPU OOB network interface".to_string()),
                interface_enabled: Some(true),
                mac_address: Some(oob_mac),
                uefi_device_path: None,
            }],
            manufacturer: None,
            model: None,
            serial_number: Some(serial_number.to_string()),
            attributes: ComputerSystemAttributes {
                nic_mode: Some(NicMode::Dpu),
                http_dev1_interface: None,
            },
            pcie_devices: vec![],
            base_mac: Some("a088c208804c".to_string()),
            power_state: PowerState::On,
        }],
        chassis: vec![Chassis {
            id: "Card1".to_string(),
            manufacturer: Some("Nvidia".to_string()),
            model: Some("Bluefield 3 SmartNIC Main Card".to_string()),
            part_number: Some("900-9D3B6-00CV-AA0".to_string()),
            serial_number: Some(serial_number.to_string()),
            network_adapters: vec![],
        }],
        service: vec![Service {
            id: "FirmwareInventory".to_string(),
            inventories: vec![
                Inventory {
                    id: "DPU_NIC".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("32.38.1002".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "DPU_BSP".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("4.5.0.12984".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "BMC_Firmware".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("BF-23.10-3".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "DPU_OFED".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("MLNX_OFED_LINUX-23.10-1.1.8".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "DPU_OS".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("DOCA_2.5.0_BSP_4.5.0_Ubuntu_22.04-1.20231129.prod".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "DPU_UEFI".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("4.5.0-43-geb17a52".to_string()),
                    release_date: None,
                },
            ],
        }],
        versions: HashMap::default(),
        model: None,
    };
    dpu_report.generate_machine_id(false)?;

    let explored_dpus = vec![ExploredDpu {
        bmc_ip: IpAddr::from_str("192.168.1.2")?,
        host_pf_mac_address: Some(MacAddress::from_str("a0:88:c2:08:80:70")?),
        report: dpu_report.clone(),
    }];

    let host_bmc_mac = MacAddress::from_str("a0:88:c2:08:81:97")?;
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

    let endpoint_explorer = Arc::new(FakeEndpointExplorer {
        reports: Arc::new(Mutex::new(HashMap::new())),
    });

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
    let oob_mac: MacAddress = "b8:3f:d2:90:97:a6".parse().unwrap();
    let serial_number = "MT2328XZ180R".to_string();

    let mut dpu_report = EndpointExplorationReport {
        endpoint_type: EndpointType::Bmc,
        last_exploration_error: None,
        vendor: Some(bmc_vendor::BMCVendor::Nvidia),
        machine_id: None,
        managers: vec![Manager {
            id: "Bluefield_BMC".to_string(),
            ethernet_interfaces: vec![EthernetInterface {
                id: Some("eth0".to_string()),
                description: Some("Management Network Interface".to_string()),
                interface_enabled: Some(true),
                mac_address: Some("a0:88:c2:08:80:90".parse().unwrap()),
                uefi_device_path: None,
            }],
        }],
        systems: vec![ComputerSystem {
            id: "Bluefield".to_string(),
            ethernet_interfaces: vec![EthernetInterface {
                id: Some("oob_net0".to_string()),
                description: Some("1G DPU OOB network interface".to_string()),
                interface_enabled: Some(true),
                mac_address: Some(oob_mac),
                uefi_device_path: None,
            }],
            manufacturer: None,
            model: None,
            serial_number: Some(serial_number.to_string()),
            attributes: ComputerSystemAttributes {
                nic_mode: Some(NicMode::Dpu),
                http_dev1_interface: None,
            },
            pcie_devices: vec![],
            base_mac: Some("a088c208804c".to_string()),
            power_state: PowerState::On,
        }],
        chassis: vec![Chassis {
            id: "Card1".to_string(),
            manufacturer: Some("Nvidia".to_string()),
            model: Some("Bluefield 3 SmartNIC Main Card".to_string()),
            part_number: Some("900-9D3B6-00CV-AA0".to_string()),
            serial_number: Some(serial_number.to_string()),
            network_adapters: vec![],
        }],
        service: vec![Service {
            id: "FirmwareInventory".to_string(),
            inventories: vec![
                Inventory {
                    id: "DPU_NIC".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("32.38.1002".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "DPU_BSP".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("4.5.0.12984".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "BMC_Firmware".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("BF-23.10-3".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "DPU_OFED".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("MLNX_OFED_LINUX-23.10-1.1.8".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "DPU_OS".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("DOCA_2.5.0_BSP_4.5.0_Ubuntu_22.04-1.20231129.prod".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "DPU_UEFI".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("4.5.0-43-geb17a52".to_string()),
                    release_date: None,
                },
            ],
        }],
        versions: HashMap::default(),
        model: None,
    };
    dpu_report.generate_machine_id(false)?;
    let dpu_machine_id = dpu_report.machine_id.clone().unwrap();

    let explored_dpus = vec![ExploredDpu {
        bmc_ip: IpAddr::from_str("192.168.1.2")?,
        host_pf_mac_address: Some(MacAddress::from_str("a0:88:c2:08:80:70")?),
        report: dpu_report.clone(),
    }];

    let host_bmc_mac = MacAddress::from_str("a0:88:c2:08:81:97")?;
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

    let endpoint_explorer = Arc::new(FakeEndpointExplorer {
        reports: Arc::new(Mutex::new(HashMap::new())),
    });

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
            mac_address: oob_mac.to_string(),
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
    let host_report = EndpointExplorationReport {
        endpoint_type: EndpointType::Bmc,
        last_exploration_error: None,
        vendor: Some(bmc_vendor::BMCVendor::Nvidia),
        machine_id: None,
        managers: vec![Manager {
            id: "BMC".to_string(),
            ethernet_interfaces: vec![],
        }],
        systems: vec![ComputerSystem {
            id: "Dell".to_string(),
            ethernet_interfaces: vec![
                EthernetInterface {
                    id: Some("eth0".to_string()),
                    description: Some("Interface 1".to_string()),
                    interface_enabled: Some(true),
                    mac_address: Some("a0:88:c2:08:80:70".parse().unwrap()),
                    uefi_device_path: Some(
                        UefiDevicePath::from_str(
                            "PciRoot(0x8)/Pci(0x2,0xa)/Pci(0x1,0x1)/MAC(A088C208545C,0x1)",
                        )
                        .unwrap(),
                    ),
                },
                EthernetInterface {
                    id: Some("eth1".to_string()),
                    description: Some("Interface 2".to_string()),
                    interface_enabled: Some(true),
                    mac_address: Some("a0:88:c2:08:80:71".parse().unwrap()),
                    uefi_device_path: Some(
                        UefiDevicePath::from_str(
                            "PciRoot(0x8)/Pci(0x2,0xa)/Pci(0x0,0x2)/MAC(A088C208545C,0x1)",
                        )
                        .unwrap(),
                    ),
                },
            ],
            manufacturer: None,
            model: None,
            serial_number: Some("TESTSERIALNUM".to_string()),
            attributes: ComputerSystemAttributes {
                nic_mode: Some(NicMode::Dpu),
                http_dev1_interface: None,
            },
            pcie_devices: vec![],
            base_mac: Some("a088c208804c".to_string()),
            power_state: PowerState::On,
        }],
        chassis: vec![Chassis {
            id: "Card1".to_string(),
            manufacturer: Some("Nvidia".to_string()),
            model: Some("Bluefield 3 SmartNIC Main Card".to_string()),
            part_number: Some("900-9D3B6-00CV-AAA".to_string()),
            serial_number: Some("TESTSERIALNUM".to_string()),
            network_adapters: vec![],
        }],
        service: vec![Service {
            id: "FirmwareInventory".to_string(),
            inventories: vec![
                Inventory {
                    id: "DPU_NIC".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("32.38.1002".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "DPU_BSP".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("4.5.0.12984".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "BMC_Firmware".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("BF-23.10-3".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "DPU_OFED".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("MLNX_OFED_LINUX-23.10-1.1.8".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "DPU_OS".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("DOCA_2.5.0_BSP_4.5.0_Ubuntu_22.04-1.20231129.prod".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "DPU_UEFI".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("4.5.0-43-geb17a52".to_string()),
                    release_date: None,
                },
            ],
        }],
        versions: HashMap::default(),
        model: None,
    };

    const NUM_DPUS: usize = 2;

    let env = common::api_fixtures::create_test_env(pool).await;
    let _underlay_segment = create_underlay_network_segment(&env).await;
    let _admin_segment = create_admin_network_segment(&env).await;
    let mut txn = env.pool.begin().await?;
    let mut oob_interfaces = Vec::new();
    let mut explored_dpus = Vec::new();

    for i in 0..NUM_DPUS {
        let oob_mac = MacAddress::from_str(format!("a0:88:c2:08:80:9{i}").as_str())?;
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

        let serial_number = format!("MT2328XZ18{i}R");

        let mut dpu_report = EndpointExplorationReport {
            endpoint_type: EndpointType::Bmc,
            last_exploration_error: None,
            vendor: Some(bmc_vendor::BMCVendor::Nvidia),
            machine_id: None,
            managers: vec![Manager {
                id: "Bluefield_BMC".to_string(),
                ethernet_interfaces: vec![EthernetInterface {
                    id: Some("eth0".to_string()),
                    description: Some("Management Network Interface".to_string()),
                    interface_enabled: Some(true),
                    mac_address: Some(format!("a0:88:c2:08:80:9{}", i).parse().unwrap()),
                    uefi_device_path: Some(
                        UefiDevicePath::from_str(&format!(
                            "PciRoot(0x8)/Pci(0x2,0xa)/Pci(0x0,0x{:x})/MAC(A088C208545C,0x1)",
                            i
                        ))
                        .unwrap(),
                    ),
                }],
            }],
            systems: vec![ComputerSystem {
                id: "Bluefield".to_string(),
                ethernet_interfaces: Vec::new(),
                manufacturer: None,
                model: None,
                serial_number: Some(serial_number.to_string()),
                attributes: ComputerSystemAttributes {
                    nic_mode: Some(NicMode::Dpu),
                    http_dev1_interface: None,
                },
                pcie_devices: vec![],
                base_mac: Some("a088c208804c".to_string()),
                power_state: PowerState::On,
            }],
            chassis: vec![Chassis {
                id: "Card1".to_string(),
                manufacturer: Some("Nvidia".to_string()),
                model: Some("Bluefield 3 SmartNIC Main Card".to_string()),
                part_number: Some(format!("900-9D3B6-00CV-AA{}", i).to_string()),
                serial_number: Some(serial_number.to_string()),
                network_adapters: vec![],
            }],
            service: vec![Service {
                id: "FirmwareInventory".to_string(),
                inventories: vec![
                    Inventory {
                        id: "DPU_NIC".to_string(),
                        description: Some("Host image".to_string()),
                        version: Some("32.38.1002".to_string()),
                        release_date: None,
                    },
                    Inventory {
                        id: "DPU_BSP".to_string(),
                        description: Some("Host image".to_string()),
                        version: Some("4.5.0.12984".to_string()),
                        release_date: None,
                    },
                    Inventory {
                        id: "BMC_Firmware".to_string(),
                        description: Some("Host image".to_string()),
                        version: Some("BF-23.10-3".to_string()),
                        release_date: None,
                    },
                    Inventory {
                        id: "DPU_OFED".to_string(),
                        description: Some("Host image".to_string()),
                        version: Some("MLNX_OFED_LINUX-23.10-1.1.8".to_string()),
                        release_date: None,
                    },
                    Inventory {
                        id: "DPU_OS".to_string(),
                        description: Some("Host image".to_string()),
                        version: Some(
                            "DOCA_2.5.0_BSP_4.5.0_Ubuntu_22.04-1.20231129.prod".to_string(),
                        ),
                        release_date: None,
                    },
                    Inventory {
                        id: "DPU_UEFI".to_string(),
                        description: Some("Host image".to_string()),
                        version: Some("4.5.0-43-geb17a52".to_string()),
                        release_date: None,
                    },
                ],
            }],
            versions: HashMap::default(),
            model: None,
        };
        dpu_report.generate_machine_id(false)?;
        explored_dpus.push(ExploredDpu {
            bmc_ip: IpAddr::from_str(format!("192.168.1.{i}").as_str())?,
            host_pf_mac_address: Some(MacAddress::from_str(
                format!("a0:88:c2:08:80:7{i}").as_str(),
            )?),
            report: dpu_report.clone(),
        })
    }

    let expected_mac: MacAddress = "a0:88:c2:08:80:71".parse().unwrap();
    let mac = host_report
        .fetch_host_primary_interface_mac(&explored_dpus)
        .unwrap();
    assert_eq!(mac, expected_mac);
    Ok(())
}
