use std::{
    collections::HashMap,
    net::IpAddr,
    net::SocketAddr,
    str::FromStr,
    sync::{Arc, Mutex},
};

use carbide::{
    cfg::{
        default_dpu_models, DpuComponent, DpuComponentUpdate, DpuDesc, DpuFwUpdateConfig, DpuModel,
        SiteExplorerConfig,
    },
    db::{
        machine::{Machine, MachineSearchConfig},
        machine_interface::MachineInterface,
    },
    model::{
        machine::{BmcFirmwareUpdateSubstate, DpuDiscoveringState, FirmwareType, ManagedHostState},
        site_explorer::{
            Chassis, ComputerSystem, EndpointExplorationError, EndpointExplorationReport,
            EndpointType, EthernetInterface, ExploredManagedHost, Inventory, Manager, Service,
        },
    },
    site_explorer::{EndpointExplorer, SiteExplorer},
    state_controller::machine::handler::MachineStateHandler,
    CarbideError,
};
use mac_address::MacAddress;
use rpc::forge::{forge_server::Forge, DhcpDiscovery};
use tokio::fs::{self, File};
use tokio::io::AsyncWriteExt;

mod common;

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

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
async fn test_bmc_fw_version(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool.clone()).await;
    let _underlay_segment = create_underlay_network_segment(&env).await;
    let _admin_segment = create_admin_network_segment(&env).await;

    let endpoint_explorer = Arc::new(FakeEndpointExplorer {
        reports: Arc::new(Mutex::new(HashMap::new())),
    });

    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: true,
        override_target_ip: None,
        override_target_port: None,
    };
    let dpu_config = default_dpu_models();
    let test_meter = TestMeter::default();
    let explorer = SiteExplorer::new(
        env.credential_provider.clone(),
        env.pool.clone(),
        Some(&explorer_config),
        &dpu_config,
        test_meter.meter(),
        endpoint_explorer.clone(),
    );

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
        }],
        chassis: vec![Chassis {
            id: "Card1".to_string(),
            manufacturer: Some("Nvidia".to_string()),
            model: Some("Bluefield 2 SmartNIC Main Card".to_string()),
            part_number: Some("MBF2H536C-CECOT      ".to_string()),
            serial_number: Some("MT2242XZ00PE            ".to_string()),
            network_adapters: vec![],
        }],
        service: vec![Service {
            id: "FirmwareInventory".to_string(),
            inventories: vec![
                Inventory {
                    id: "63b6c138_BMC_Firmware".to_string(),
                    description: Some("BMC image".to_string()),
                    version: Some("bf-23.05-5-0-g87a8acd1708.1701259870.8631477".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "DPU_SYS_IMAGE".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("".to_string()),
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

    let exploration_report = ExploredManagedHost {
        host_bmc_ip: IpAddr::from_str("192.168.1.1")?,
        dpu_bmc_ip: IpAddr::from_str("192.168.1.2")?,
        host_pf_mac_address: Some(MacAddress::from_str("a0:88:c2:08:80:72")?),
    };

    let handled_uefi_err = match explorer
        .create_machine_pair(&dpu_report, &exploration_report, &env.pool)
        .await
    {
        Err(CarbideError::UnsupportedFirmwareVersion(_)) => true,
        Ok(_) | Err(_) => false,
    };
    assert!(handled_uefi_err);

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
async fn test_uefi_fw_version(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool).await;
    let _underlay_segment = create_underlay_network_segment(&env).await;
    let _admin_segment = create_admin_network_segment(&env).await;

    let endpoint_explorer = Arc::new(FakeEndpointExplorer {
        reports: Arc::new(Mutex::new(HashMap::new())),
    });

    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: true,
        override_target_ip: None,
        override_target_port: None,
    };
    let dpu_config = default_dpu_models();
    let test_meter = TestMeter::default();
    let explorer = SiteExplorer::new(
        env.credential_provider.clone(),
        env.pool.clone(),
        Some(&explorer_config),
        &dpu_config,
        test_meter.meter(),
        endpoint_explorer.clone(),
    );

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
                    id: "BMC_Firmware".to_string(),
                    description: Some("BMC image".to_string()),
                    version: Some("BF-23.10-3".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "DPU_SYS_IMAGE".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "DPU_UEFI".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("3.9.3-7-g8f2d8ca".to_string()),
                    release_date: None,
                },
            ],
        }],
    };
    dpu_report.generate_machine_id();

    assert!(dpu_report.machine_id.as_ref().is_some());

    let exploration_report = ExploredManagedHost {
        host_bmc_ip: IpAddr::from_str("192.168.1.1")?,
        dpu_bmc_ip: IpAddr::from_str("192.168.1.2")?,
        host_pf_mac_address: Some(MacAddress::from_str("a0:88:c2:08:80:72")?),
    };

    let handled_uefi_err = match explorer
        .create_machine_pair(&dpu_report, &exploration_report, &env.pool)
        .await
    {
        Err(CarbideError::UnsupportedFirmwareVersion(_)) => true,
        Ok(_) | Err(_) => false,
    };
    assert!(handled_uefi_err);

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
async fn test_bmc_fw_update(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = common::api_fixtures::create_test_env(pool).await;
    let _underlay_segment = create_underlay_network_segment(&env).await;
    let _admin_segment = create_admin_network_segment(&env).await;

    let endpoint_explorer = Arc::new(FakeEndpointExplorer {
        reports: Arc::new(Mutex::new(HashMap::new())),
    });

    let explorer_config = SiteExplorerConfig {
        enabled: true,
        explorations_per_run: 2,
        concurrent_explorations: 1,
        run_interval: std::time::Duration::from_secs(1),
        create_machines: true,
        override_target_ip: None,
        override_target_port: None,
    };
    let dpu_config = default_dpu_models();
    let test_meter = TestMeter::default();
    let explorer = SiteExplorer::new(
        env.credential_provider.clone(),
        env.pool.clone(),
        Some(&explorer_config),
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
                    id: "DPU_SYS_IMAGE".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("b83f:d203:0090:97a4".to_string()),
                    release_date: None,
                },
                Inventory {
                    id: "DPU_UEFI".to_string(),
                    description: Some("Host image".to_string()),
                    version: Some("4.5.0-46-gf57517d".to_string()),
                    release_date: None,
                },
            ],
        }],
    };
    dpu_report.generate_machine_id();

    assert!(dpu_report.machine_id.as_ref().is_some());

    let exploration_report = ExploredManagedHost {
        host_bmc_ip: IpAddr::from_str("192.168.1.1")?,
        dpu_bmc_ip: IpAddr::from_str("192.168.1.2")?,
        host_pf_mac_address: Some(MacAddress::from_str("a0:88:c2:08:80:72")?),
    };

    assert!(
        explorer
            .create_machine_pair(&dpu_report, &exploration_report, &env.pool)
            .await?
    );

    let mut txn = env.pool.begin().await.unwrap();
    let dpu_machine = Machine::find_one(
        &mut txn,
        dpu_report.machine_id.as_ref().unwrap(),
        MachineSearchConfig::default(),
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

    let handler = MachineStateHandler::new(
        chrono::Duration::minutes(1),
        true,
        true,
        DpuFwUpdateConfig {
            dpu_bf2_bmc_firmware_update_version: HashMap::new(),
            dpu_bf3_bmc_firmware_update_version: HashMap::from([
                ("BMC_Firmware".to_string(), "23.10-5".to_string()),
                ("Bluefield_FW_ERoT".to_string(), "02.0152.0000".to_string()),
            ]),
            firmware_location: ".".to_string(),
        },
        HashMap::from([
            (
                DpuModel::BlueField2,
                DpuDesc {
                    ..Default::default()
                },
            ),
            (
                DpuModel::BlueField3,
                DpuDesc {
                    component_update: Some(HashMap::from([(
                        DpuComponent::Bmc,
                        DpuComponentUpdate {
                            version: Some("23.10-5".to_string()),
                            path: "./bf3-bmc.fwpkg".to_string(),
                        },
                    )])),
                    ..Default::default()
                },
            ),
        ]),
        env.reachability_params,
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

    env.run_machine_state_controller_iteration(handler.clone())
        .await;

    let dpu_machine = Machine::find_one(
        &mut txn,
        dpu_report.machine_id.as_ref().unwrap(),
        MachineSearchConfig::default(),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(
        dpu_machine.current_state(),
        ManagedHostState::DpuDiscoveringState {
            discovering_state: DpuDiscoveringState::Configuring,
        }
    );

    // Fake FW files
    let bmc_fw_filename = "bf3-bmc.fwpkg";
    let mut bmc_fw = File::create(bmc_fw_filename).await?;
    bmc_fw.write_all(b"Fake BMC FW").await?;

    env.run_machine_state_controller_iteration(handler.clone())
        .await;

    let dpu_machine = Machine::find_one(
        &mut txn,
        dpu_report.machine_id.as_ref().unwrap(),
        MachineSearchConfig::default(),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(
        dpu_machine.current_state(),
        ManagedHostState::DpuDiscoveringState {
            discovering_state: DpuDiscoveringState::BmcFirmwareUpdate {
                substate: BmcFirmwareUpdateSubstate::WaitForUpdateCompletion {
                    firmware_type: FirmwareType::Bmc,
                    task_id: "0".to_string()
                }
            },
        }
    );

    env.run_machine_state_controller_iteration(handler.clone())
        .await;

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
            discovering_state: DpuDiscoveringState::BmcFirmwareUpdate {
                substate: BmcFirmwareUpdateSubstate::Reboot { count: 0 }
            },
        }
    );

    env.run_machine_state_controller_iteration(handler.clone())
        .await;

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

    // After BMC FW update make sure it returns back to Configuring state
    assert_eq!(
        dpu_machine.current_state(),
        ManagedHostState::DpuDiscoveringState {
            discovering_state: DpuDiscoveringState::Configuring,
        }
    );

    fs::remove_file(bmc_fw_filename).await?;
    Ok(())
}
/// EndpointExplorer which returns predefined data
struct FakeEndpointExplorer {
    reports: Arc<
        Mutex<HashMap<SocketAddr, Result<EndpointExplorationReport, EndpointExplorationError>>>,
    >,
}

#[async_trait::async_trait]
impl EndpointExplorer for FakeEndpointExplorer {
    async fn explore_endpoint(
        &self,
        address: SocketAddr,
        _interface: &MachineInterface,
        _last_report: Option<&EndpointExplorationReport>,
    ) -> Result<EndpointExplorationReport, EndpointExplorationError> {
        tracing::info!("Endpoint {address} is getting explored");
        let guard = self.reports.lock().unwrap();
        let res = guard.get(&address).unwrap();
        res.clone()
    }
}
