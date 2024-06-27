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

use std::{
    collections::HashMap,
    net::IpAddr,
    net::SocketAddr,
    str::FromStr,
    sync::{Arc, Mutex},
};

use carbide::{
    cfg::{default_dpu_models, SiteExplorerConfig},
    db::{
        expected_machine::ExpectedMachine,
        explored_endpoints::DbExploredEndpoint,
        machine::{Machine, MachineSearchConfig},
        machine_interface::MachineInterface,
        machine_topology::MachineTopology,
    },
    model::{
        machine::{machine_id::MachineId, DpuDiscoveringState, MachineState, ManagedHostState},
        site_explorer::{
            Chassis, ComputerSystem, ComputerSystemAttributes, EndpointExplorationError,
            EndpointExplorationReport, EndpointType, EthernetInterface, ExploredDpu,
            ExploredManagedHost, Inventory, Manager, NetworkAdapter, NicMode, Service,
        },
    },
    site_explorer::{EndpointExplorer, SiteExplorationMetrics, SiteExplorer},
    state_controller::machine::handler::MachineStateHandler,
};
use mac_address::MacAddress;
use rpc::{
    forge::{forge_server::Forge, DhcpDiscovery, GetSiteExplorationRequest},
    site_explorer::ExploredDpu as RpcExploredDpu,
    site_explorer::ExploredManagedHost as RpcExploredManagedHost,
    BlockDevice, DiscoveryData, DiscoveryInfo, MachineDiscoveryInfo,
};

mod common;
use common::api_fixtures::TestEnv;
use tonic::Request;

use crate::common::{
    api_fixtures::network_segment::{
        create_admin_network_segment, create_underlay_network_segment,
    },
    test_meter::TestMeter,
};

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

struct FakeMachine {
    pub mac: String,
    pub dhcp_vendor: String,
    pub segment: uuid::Uuid,
    pub ip: String,
}

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
async fn test_site_explorer(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;

    let underlay_segment = create_underlay_network_segment(&env).await;
    let admin_segment = create_admin_network_segment(&env).await;

    // Let's create 3 machines on the underlay, and 1 on the admin network
    // The 1 on the admin network is not supposed to be searched. This is verified
    // by providing no mocked exploration data for this machine, which would lead
    // to a panic if the machine is queried
    let mut machines = vec![
        FakeMachine {
            mac: "B8:3F:D2:90:97:A6".to_string(),
            dhcp_vendor: "Vendor1".to_string(),
            segment: underlay_segment,
            ip: String::new(),
        },
        FakeMachine {
            mac: "AA:AB:AC:AD:AA:02".to_string(),
            dhcp_vendor: "Vendor2".to_string(),
            segment: underlay_segment,
            ip: String::new(),
        },
        FakeMachine {
            mac: "AA:AB:AC:AD:AA:03".to_string(),
            dhcp_vendor: "Vendor3".to_string(),
            segment: underlay_segment,
            ip: String::new(),
        },
        FakeMachine {
            mac: "AA:AB:AC:AD:BB:01".to_string(),
            dhcp_vendor: "VendorInvalidSegment".to_string(),
            segment: admin_segment,
            ip: String::new(),
        },
    ];

    for machine in &mut machines {
        let response = env
            .api
            .discover_dhcp(tonic::Request::new(DhcpDiscovery {
                mac_address: machine.mac.clone(),
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
        MachineInterface::count_by_segment_id(&mut txn, &underlay_segment)
            .await
            .unwrap(),
        3
    );
    assert_eq!(
        MachineInterface::count_by_segment_id(&mut txn, &admin_segment)
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
                        mac_address: Some("b8:3f:d2:90:97:a6".to_string()),
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
                    },
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
                systems: Vec::new(),
                chassis: Vec::new(),
                service: Vec::new(),
            }),
        );
    }

    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: carbide::dynamic_settings::create_machines(true),
        override_target_ip: None,
        override_target_port: None,
    };
    let dpu_config = default_dpu_models();
    let test_meter = TestMeter::default();
    let explorer = SiteExplorer::new(
        env.pool.clone(),
        explorer_config,
        &dpu_config,
        test_meter.meter(),
        endpoint_explorer.clone(),
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
        *m0 = Err(EndpointExplorationError::Unreachable);

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
                    mac_address: Some("c8:4b:d6:7a:dc:bc".to_string()),
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
                        mac_address: Some("c8:4b:d6:7b:ab:93".to_string()),
                    },
                    EthernetInterface {
                        id: Some("NIC.Embedded.1-1-1".to_string()),
                        description: Some("Embedded NIC 1 Port 1 Partition 1".to_string()),
                        interface_enabled: Some(false),
                        mac_address: Some("c8:4b:d6:7b:ab:92".to_string()),
                    },
                    EthernetInterface {
                        id: Some("NIC.Slot.5-1".to_string()),
                        description: Some("NIC in Slot 5 Port 1".to_string()),
                        interface_enabled: Some(true),
                        mac_address: Some("b8:3f:d2:90:97:a4".to_string()),
                    },
                ],
                attributes: ComputerSystemAttributes::default(),
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
                        id: "BMC-Primary".to_string(),
                        description: Some("The information of BMC (Primary) firmware.".to_string()),
                        version: Some("38U-3.86".to_string()),
                        release_date: Some("2023-09-12T00:00:00Z".to_string()),
                    },
                ],
            }],
            machine_id: None,
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
    txn.commit().await?;
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
                    EndpointExplorationError::Unreachable
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

    assert_eq!(report.managed_hosts.len(), 1);
    let managed_host = report.managed_hosts.clone().remove(0);
    assert_eq!(
        managed_host,
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
        test_meter
            .formatted_metric("forge_site_exploration_identified_managed_hosts_count")
            .unwrap(),
        "1"
    );

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc",))]
async fn test_site_explorer_creates_managed_host(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool).await;
    let _underlay_segment = create_underlay_network_segment(&env).await;
    let _admin_segment = create_admin_network_segment(&env).await;

    let endpoint_explorer = Arc::new(FakeEndpointExplorer {
        reports: Arc::new(Mutex::new(HashMap::new())),
    });

    let dpu_config = default_dpu_models();
    let test_meter = TestMeter::default();
    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: carbide::dynamic_settings::create_machines(true),
        override_target_ip: None,
        override_target_port: None,
    };

    let explorer = SiteExplorer::new(
        env.pool.clone(),
        explorer_config,
        &dpu_config,
        test_meter.meter(),
        endpoint_explorer.clone(),
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
                mac_address: Some("a0:88:c2:08:80:97".to_string()),
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
            },
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
    };
    dpu_report.generate_machine_id();

    assert!(dpu_report.machine_id.as_ref().is_some());
    assert_eq!(
        dpu_report.machine_id.as_ref().unwrap().to_string(),
        "fm100ds3gfip02lfgleidqoitqgh8d8mdc4a3j2tdncbjrfjtvrrhn2kleg".to_string(),
    );

    let exploration_report = ExploredManagedHost {
        host_bmc_ip: IpAddr::from_str("192.168.1.1")?,
        dpus: vec![ExploredDpu {
            bmc_ip: IpAddr::from_str(response.address.as_str())?,
            host_pf_mac_address: Some(MacAddress::from_str("a0:88:c2:08:80:72")?),
            report: dpu_report.clone(),
        }],
    };

    assert!(
        explorer
            .create_managed_host(&exploration_report, &env.pool)
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
            discovering_state: DpuDiscoveringState::Initializing,
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
            discovering_state: DpuDiscoveringState::Initializing,
        }
    );
    assert!(host_machine.bmc_info().ip.is_some());

    // 2nd creation does nothing
    assert!(
        !explorer
            .create_managed_host(&exploration_report, &env.pool)
            .await?
    );

    // Run ManagedHost state iteration
    let handler = MachineStateHandler::new(
        chrono::Duration::minutes(1),
        true,
        true,
        default_dpu_models(),
        env.reachability_params,
        env.attestation_enabled,
    );
    env.run_machine_state_controller_iteration(handler.clone())
        .await;

    let dpu_machine = Machine::find_one(&mut txn, dpu_machine.id(), MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu_machine.current_state(),
        ManagedHostState::DpuDiscoveringState {
            discovering_state: DpuDiscoveringState::Configuring,
        }
    );

    env.run_machine_state_controller_iteration(handler.clone())
        .await;

    let dpu_machine = Machine::find_one(&mut txn, dpu_machine.id(), MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        dpu_machine.current_state(),
        ManagedHostState::DPUNotReady {
            machine_state: MachineState::Init,
        },
    );

    let machine_interfaces = MachineInterface::find_by_mac_address(&mut txn, oob_mac).await?;
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

    let machine_interfaces = MachineInterface::find_by_mac_address(&mut txn, oob_mac).await?;
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
        ManagedHostState::DPUNotReady {
            machine_state: MachineState::Init
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

    let dpu_config = default_dpu_models();
    let test_meter = TestMeter::default();
    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: carbide::dynamic_settings::create_machines(true),
        override_target_ip: None,
        override_target_port: None,
    };

    let explorer = SiteExplorer::new(
        env.pool.clone(),
        explorer_config,
        &dpu_config,
        test_meter.meter(),
        endpoint_explorer.clone(),
    );
    let mut txn = env.pool.begin().await.unwrap();
    const NUM_DPUS: usize = 2;
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
        let oob_interface = MachineInterface::find_by_mac_address(&mut txn, oob_mac).await?;
        assert!(oob_interface[0].primary_interface());
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
                    mac_address: Some(format!("a0:88:c2:08:80:9{}", i).to_string()),
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
                },
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
        };
        dpu_report.generate_machine_id();
        explored_dpus.push(ExploredDpu {
            bmc_ip: IpAddr::from_str(format!("192.168.1.{i}").as_str())?,
            host_pf_mac_address: Some(MacAddress::from_str(
                format!("a0:88:c2:08:80:7{i}").as_str(),
            )?),
            report: dpu_report.clone(),
        })
    }

    let exploration_report = ExploredManagedHost {
        host_bmc_ip: IpAddr::from_str("192.168.1.1")?,
        dpus: explored_dpus.clone(),
    };

    assert!(
        explorer
            .create_managed_host(&exploration_report, &env.pool)
            .await?
    );

    let mut host_machine_id: Option<MachineId> = None;
    let mut dpu_machines = Vec::new();

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
        assert_eq!(
            dpu_machine.current_state(),
            ManagedHostState::DpuDiscoveringState {
                discovering_state: DpuDiscoveringState::Initializing,
            }
        );

        let host_machine = Machine::find_host_by_dpu_machine_id(&mut txn, dpu_machine.id())
            .await?
            .unwrap();
        assert_eq!(
            host_machine.current_state(),
            ManagedHostState::DpuDiscoveringState {
                discovering_state: DpuDiscoveringState::Initializing,
            }
        );
        assert!(host_machine.bmc_info().ip.is_some());
        if host_machine_id.is_none() {
            host_machine_id = Some(host_machine.id().clone());
        }

        assert_eq!(host_machine.id(), host_machine_id.as_ref().unwrap());
        dpu_machines.push(dpu_machine);
    }

    let mut interfaces_map = MachineInterface::find_by_machine_ids(
        &mut txn,
        &[host_machine_id.as_ref().unwrap().clone()],
    )
    .await?;
    let interfaces = interfaces_map
        .remove(host_machine_id.clone().as_ref().unwrap())
        .unwrap();
    assert_eq!(interfaces.len(), NUM_DPUS);
    assert!(interfaces[0].primary_interface());
    for interface in interfaces.iter().skip(1) {
        assert!(!interface.primary_interface());
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
        _interface: &MachineInterface,
        _expected: Option<ExpectedMachine>,
        _last_report: Option<&EndpointExplorationReport>,
    ) -> Result<EndpointExplorationReport, EndpointExplorationError> {
        tracing::info!("Endpoint {bmc_ip_address} is getting explored");
        let guard = self.reports.lock().unwrap();
        let res = guard.get(&bmc_ip_address.ip()).unwrap();
        res.clone()
    }
}

async fn fetch_exploration_report(env: &TestEnv) -> rpc::site_explorer::SiteExplorationReport {
    env.api
        .get_site_exploration_report(tonic::Request::new(GetSiteExplorationRequest::default()))
        .await
        .unwrap()
        .into_inner()
}
