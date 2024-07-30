use std::{
    collections::HashMap,
    net::IpAddr,
    net::SocketAddr,
    str::FromStr,
    sync::{Arc, Mutex},
};

use carbide::{
    cfg::{FirmwareComponentType, SiteExplorerConfig},
    db::{
        expected_machine::ExpectedMachine,
        machine::{Machine, MachineSearchConfig},
        machine_interface::MachineInterface,
    },
    model::{
        machine::{BmcFirmwareUpdateSubstate, DpuDiscoveringState, ManagedHostState},
        site_explorer::{
            Chassis, ComputerSystem, ComputerSystemAttributes, EndpointExplorationError,
            EndpointExplorationReport, EndpointType, EthernetInterface, ExploredDpu,
            ExploredManagedHost, Inventory, Manager, NicMode, Service,
        },
    },
    site_explorer::{EndpointExplorer, SiteExplorationMetrics, SiteExplorer},
    state_controller::machine::handler::MachineStateHandlerBuilder,
};
use mac_address::MacAddress;
use rpc::forge::{forge_server::Forge, DhcpDiscovery};
use tempdir::TempDir;
use tokio::fs::File;
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
        create_machines: carbide::dynamic_settings::create_machines(true),
        override_target_ip: None,
        override_target_port: None,
    };
    let test_meter = TestMeter::default();
    let explorer = SiteExplorer::new(
        env.pool.clone(),
        explorer_config,
        test_meter.meter(),
        endpoint_explorer.clone(),
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

    // Expected DPU BMC update scenario
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
            ethernet_interfaces: vec![EthernetInterface {
                id: Some("oob_net0".to_string()),
                description: Some("1G DPU OOB network interface".to_string()),
                interface_enabled: Some(true),
                mac_address: Some(oob_mac.to_string()),
            }],
            manufacturer: None,
            model: None,
            serial_number: Some("MT2328XZ185R".to_string()),
            attributes: ComputerSystemAttributes {
                nic_mode: Some(NicMode::Dpu),
                http_dev1_interface: None,
            },
            pcie_devices: vec![],
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
                    version: Some("BF-23.07-3".to_string()),
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

    let host_bmc_mac = MacAddress::from_str("a0:88:c2:08:81:96")?;
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
            .create_managed_host(exploration_report, &env.pool)
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
            dpu_states: carbide::model::machine::DpuDiscoveringStates {
                states: HashMap::from([(
                    dpu_machine.id().clone(),
                    DpuDiscoveringState::Initializing
                )]),
            },
        }
    );

    // Fake FW files
    let bmc_fw_filename = "bf3-bmc.fwpkg";
    let tmp_path = TempDir::new("bmc-fw-test")?;
    let bmc_fw_path = tmp_path.path().join(bmc_fw_filename);
    let mut bmc_fw = File::create(bmc_fw_path.clone()).await?;
    bmc_fw.write_all(b"Fake BMC FW").await?;

    let handler = MachineStateHandlerBuilder::builder()
        .dpu_up_threshold(chrono::Duration::minutes(1))
        .hardware_models(env.config.get_parsed_hosts())
        .reachability_params(env.reachability_params)
        .attestation_enabled(env.attestation_enabled)
        .build();

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
            dpu_states: carbide::model::machine::DpuDiscoveringStates {
                states: HashMap::from([(
                    dpu_machine.id().clone(),
                    DpuDiscoveringState::Configuring
                )]),
            },
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
            dpu_states: carbide::model::machine::DpuDiscoveringStates {
                states: HashMap::from([(
                    dpu_machine.id().clone(),
                    DpuDiscoveringState::BmcFirmwareUpdate {
                        substate: BmcFirmwareUpdateSubstate::WaitForUpdateCompletion {
                            firmware_type: FirmwareComponentType::Bmc,
                            task_id: "0".to_string()
                        }
                    }
                )]),
            },
        }
    );

    env.run_machine_state_controller_iteration(handler.clone())
        .await;
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
            dpu_states: carbide::model::machine::DpuDiscoveringStates {
                states: HashMap::from([(
                    dpu_machine.id().clone(),
                    DpuDiscoveringState::BmcFirmwareUpdate {
                        substate: BmcFirmwareUpdateSubstate::Reboot { count: 0 }
                    }
                )]),
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
            dpu_states: carbide::model::machine::DpuDiscoveringStates {
                states: HashMap::from([(
                    dpu_machine.id().clone(),
                    DpuDiscoveringState::Configuring
                )]),
            },
        }
    );

    drop(bmc_fw);
    tmp_path.close()?;
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
    async fn check_preconditions(
        &self,
        _metrics: &mut SiteExplorationMetrics,
    ) -> Result<(), EndpointExplorationError> {
        Ok(())
    }
    async fn explore_endpoint(
        &self,
        address: SocketAddr,
        _interface: &MachineInterface,
        _expected: Option<ExpectedMachine>,
        _last_report: Option<&EndpointExplorationReport>,
    ) -> Result<EndpointExplorationReport, EndpointExplorationError> {
        tracing::info!("Endpoint {address} is getting explored");
        let guard = self.reports.lock().unwrap();
        let res = guard.get(&address).unwrap();
        res.clone()
    }
}
