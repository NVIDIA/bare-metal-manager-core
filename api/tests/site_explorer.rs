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
    str::FromStr,
    sync::{Arc, Mutex},
};

use carbide::{
    cfg::SiteExplorerConfig,
    db::{
        explored_endpoints::DbExploredEndpoint,
        machine::{Machine, MachineSearchConfig},
        machine_interface::MachineInterface,
        machine_topology::MachineTopology,
    },
    model::{
        machine::{DpuDiscoveringState, MachineState, ManagedHostState},
        site_explorer::{
            Chassis, ComputerSystem, EndpointExplorationError, EndpointExplorationReport,
            EndpointType, EthernetInterface, ExploredManagedHost, Inventory, Manager,
            NetworkAdapter, Service,
        },
    },
    site_explorer::{EndpointExplorer, SiteExplorer},
    state_controller::{
        machine::handler::MachineStateHandler, metrics::IterationMetrics,
        network_segment::handler::NetworkSegmentStateHandler,
    },
};
use mac_address::MacAddress;
use rpc::{
    forge::{forge_server::Forge, DhcpDiscovery, GetSiteExplorationRequest},
    site_explorer::ExploredManagedHost as RpcExploredManagedHost,
    BlockDevice, DiscoveryData, DiscoveryInfo, MachineDiscoveryInfo,
};

mod common;
use common::{api_fixtures::TestEnv, network_segment::FIXTURE_CREATED_DOMAIN_UUID};
use tonic::Request;

use crate::common::api_fixtures::run_state_controller_iteration;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

async fn create_network_segment(
    env: &TestEnv,
    name: &str,
    prefix: &str,
    gateway: &str,
    segment_type: rpc::forge::NetworkSegmentType,
) -> uuid::Uuid {
    let request = rpc::forge::NetworkSegmentCreationRequest {
        id: None,
        mtu: Some(1500),
        name: name.to_string(),
        prefixes: vec![rpc::forge::NetworkPrefix {
            id: None,
            prefix: prefix.to_string(),
            gateway: Some(gateway.to_string()),
            reserve_first: 1,
            state: None,
            events: vec![],
            circuit_id: None,
        }],
        subdomain_id: Some(FIXTURE_CREATED_DOMAIN_UUID.into()),
        vpc_id: None,
        segment_type: segment_type as _,
    };

    let response = env
        .api
        .create_network_segment(tonic::Request::new(request))
        .await
        .expect("Unable to create network segment")
        .into_inner();
    let segment_id: uuid::Uuid = response.id.unwrap().try_into().unwrap();

    // Get the segment into ready state
    let handler = NetworkSegmentStateHandler::new(
        chrono::Duration::milliseconds(500),
        env.common_pools.ethernet.pool_vlan_id.clone(),
        env.common_pools.ethernet.pool_vni.clone(),
    );
    env.run_network_segment_controller_iteration(segment_id, &handler)
        .await;
    env.run_network_segment_controller_iteration(segment_id, &handler)
        .await;

    segment_id
}

async fn create_underlay_network_segment(env: &TestEnv) -> uuid::Uuid {
    create_network_segment(
        env,
        "UNDERLAY",
        "192.0.1.0/24",
        "192.0.1.1",
        rpc::forge::NetworkSegmentType::Underlay,
    )
    .await
}

async fn create_admin_network_segment(env: &TestEnv) -> uuid::Uuid {
    create_network_segment(
        env,
        "ADMIN",
        "192.0.2.0/24",
        "192.0.2.1",
        rpc::forge::NetworkSegmentType::Admin,
    )
    .await
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
            mac: "AA:AB:AC:AD:BB:001".to_string(),
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
            .await
            .unwrap()
            .into_inner();
        tracing::info!(
            "DHCP with mac {} assigned ip {}",
            machine.mac,
            response.address
        );
        machine.ip = response.address;
    }

    let mut txn = pool.begin().await?;
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

    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: 1,
        create_machines: true,
    };
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
                vendor: Some("NVIDIA".to_string()),
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
                vendor: Some("Vendor3".to_string()),
                machine_id: None,
                managers: Vec::new(),
                systems: Vec::new(),
                chassis: Vec::new(),
                service: Vec::new(),
            }),
        );
    }

    let meter = opentelemetry::global::meter("test");
    let explorer = SiteExplorer::new(
        pool.clone(),
        Some(&explorer_config),
        meter,
        endpoint_explorer.clone(),
    );

    explorer.run_single_iteration().await.unwrap();
    // Since we configured a limit of 2 entries, we should have those 2 results now
    let mut txn = pool.begin().await?;
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

    // Running again should yield all 3 entries
    explorer.run_single_iteration().await.unwrap();
    // Since we configured a limit of 2 entries, we should have those 2 results now
    let mut txn = pool.begin().await?;
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
            vendor: Some("Vendor2".to_string()),
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

    explorer.run_single_iteration().await.unwrap();
    explorer.run_single_iteration().await.unwrap();
    let mut txn = pool.begin().await?;
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
                assert_eq!(report.report.vendor, Some("NVIDIA".to_string()));
                assert_eq!(
                    report.report.last_exploration_error.clone().unwrap(),
                    EndpointExplorationError::Unreachable
                );
            }
            a if a == machines[1].ip => {
                assert_eq!(report.report.vendor, Some("Vendor2".to_string()));
                assert!(report.report.last_exploration_error.is_none());
            }
            a if a == machines[2].ip => {
                assert_eq!(report.report.vendor, Some("Vendor3".to_string()));
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
        }
    );

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc",))]
async fn test_site_explorer_creates_managed_host(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;
    let _underlay_segment = create_underlay_network_segment(&env).await;
    let _admin_segment = create_admin_network_segment(&env).await;

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
        vendor: Some("NVIDIA".to_string()),
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
        dpu_bmc_ip: IpAddr::from_str("192.168.1.2")?,
        host_pf_mac_address: Some(MacAddress::from_str("a0:88:c2:08:80:72")?),
    };

    assert!(SiteExplorer::create_machine_pair(&dpu_report, &exploration_report, &env.pool).await?);
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
        "192.168.1.2".to_string()
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
    assert_eq!(host_machine.bmc_info().ip, None);
    assert_eq!(host_machine.hardware_info(), None);

    // 2nd creation does nothing
    assert!(!SiteExplorer::create_machine_pair(&dpu_report, &exploration_report, &env.pool).await?);

    // Run ManagedHost state iteration
    let handler = MachineStateHandler::new(chrono::Duration::minutes(1), true, true);
    let services = Arc::new(env.state_handler_services());
    let mut iteration_metrics = IterationMetrics::default();
    run_state_controller_iteration(
        &services,
        &pool,
        &env.machine_state_controller_io,
        host_machine.id().clone(),
        &handler,
        &mut iteration_metrics,
    )
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

    run_state_controller_iteration(
        &services,
        &pool,
        &env.machine_state_controller_io,
        host_machine.id().clone(),
        &handler,
        &mut iteration_metrics,
    )
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
            discovery_data: Some(DiscoveryData::Info(discovery_info)),
            source_ip: String::new(),
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

/// EndpointExplorer which returns predefined data
struct FakeEndpointExplorer {
    reports:
        Arc<Mutex<HashMap<IpAddr, Result<EndpointExplorationReport, EndpointExplorationError>>>>,
}

#[async_trait::async_trait]
impl EndpointExplorer for FakeEndpointExplorer {
    async fn explore_endpoint(
        &self,
        address: &IpAddr,
        _interface: &MachineInterface,
        _last_report: Option<&EndpointExplorationReport>,
    ) -> Result<EndpointExplorationReport, EndpointExplorationError> {
        tracing::info!("Endpoint {address} is getting explored");
        let guard = self.reports.lock().unwrap();
        let res = guard.get(address).unwrap();
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
