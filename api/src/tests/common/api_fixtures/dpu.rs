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

//! Contains DPU related fixtures

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::atomic::{AtomicU32, Ordering},
};

use crate::{
    db::{
        self,
        machine::{Machine, MachineSearchConfig},
    },
    model::{
        hardware_info::HardwareInfo,
        machine::{machine_id::try_parse_machine_id, DpuInitState, MachineState, ManagedHostState},
        site_explorer::{
            Chassis, ComputerSystem, ComputerSystemAttributes, EndpointExplorationError,
            EndpointExplorationReport, EndpointType, EthernetInterface, Inventory, Manager,
            NicMode, PowerState, Service, UefiDevicePath,
        },
    },
};
use forge_uuid::machine::MachineId;
use libredfish::{OData, PCIeDevice};
use mac_address::MacAddress;
use rpc::{
    forge::{
        forge_server::Forge,
        machine_credentials_update_request::{CredentialPurpose, Credentials},
        DhcpDiscovery, MachineCredentialsUpdateRequest,
    },
    DiscoveryData, DiscoveryInfo, MachineDiscoveryInfo,
};
use tonic::Request;

use crate::tests::common::{
    api_fixtures::{
        discovery_completed, forge_agent_control, managed_host::ManagedHostConfig,
        network_configured, update_bmc_metadata, TestEnv, FIXTURE_DHCP_RELAY_ADDRESS,
    },
    mac_address_pool,
};

pub const FIXTURE_DPU_BMC_VERSION: &str = "2.1";
pub const FIXTURE_DPU_BMC_FIRMWARE_VERSION: &str = "3.2";

pub const FIXTURE_DPU_BMC_ADMIN_USER_NAME: &str = "forge_admin";

pub const FIXTURE_DPU_SSH_USERNAME: &str = "forge";
pub const FIXTURE_DPU_SSH_PASSWORD: &str = "asdhjkf";

pub const FIXTURE_DPU_HBN_USERNAME: &str = "cumulus";
pub const FIXTURE_DPU_HBN_PASSWORD: &str = "a9123";

/// DPU firmware version that is reported by DPU objects created via `create_dpu_hardware_info`.
pub const DEFAULT_DPU_FIRMWARE_VERSION: &str = "1.2.3";

/// The version identifier that is used by dpu-agent in unit-tests
pub const TEST_DPU_AGENT_VERSION: &str = "test";

/// The version of HBN reported in unit-tests
pub const TEST_DOCA_HBN_VERSION: &str = "1.5.0-doca2.2.0";
/// The version of doca-telemetry reported in unit-tests
pub const TEST_DOCA_TELEMETRY_VERSION: &str = "1.14.2-doca2.2.0";

const DPU_INFO_JSON: &[u8] =
    include_bytes!("../../../../src/model/hardware_info/test_data/dpu_info.json");

static NEXT_DPU_SERIAL: AtomicU32 = AtomicU32::new(1);

#[derive(Clone, Debug)]
pub struct DpuConfig {
    pub serial: String,
    pub host_mac_address: MacAddress,
    pub oob_mac_address: MacAddress,
    pub bmc_mac_address: MacAddress,
    pub last_exploration_error: Option<EndpointExplorationError>,
    pub override_hosts_uefi_device_path: Option<UefiDevicePath>,
}

impl DpuConfig {
    pub fn with_serial(serial: String) -> Self {
        Self {
            serial,
            ..Default::default()
        }
    }
}

impl Default for DpuConfig {
    fn default() -> Self {
        Self {
            serial: format!(
                "MT2333X{:05X}",
                NEXT_DPU_SERIAL.fetch_add(1, Ordering::Relaxed)
            ),
            host_mac_address: mac_address_pool::HOST_MAC_ADDRESS_POOL.allocate(),
            oob_mac_address: mac_address_pool::DPU_OOB_MAC_ADDRESS_POOL.allocate(),
            bmc_mac_address: mac_address_pool::DPU_BMC_MAC_ADDRESS_POOL.allocate(),
            last_exploration_error: None,
            override_hosts_uefi_device_path: None,
        }
    }
}

impl From<&DpuConfig> for HardwareInfo {
    fn from(value: &DpuConfig) -> Self {
        let mut info = serde_json::from_slice::<HardwareInfo>(DPU_INFO_JSON).unwrap();
        info.dpu_info.as_mut().unwrap().factory_mac_address = value.host_mac_address.to_string();
        info.dpu_info.as_mut().unwrap().firmware_version = DEFAULT_DPU_FIRMWARE_VERSION.to_owned();
        info.dmi_data.as_mut().unwrap().product_serial = value.serial.clone();
        assert!(info.is_dpu());
        info
    }
}

impl From<DpuConfig> for EndpointExplorationReport {
    fn from(value: DpuConfig) -> Self {
        Self {
            endpoint_type: EndpointType::Bmc,
            last_exploration_error: value.last_exploration_error,
            last_exploration_latency: None,
            vendor: Some(bmc_vendor::BMCVendor::Nvidia),
            machine_id: None,
            managers: vec![Manager {
                id: "bmc".to_string(),
                ethernet_interfaces: vec![EthernetInterface {
                    id: Some("eth0".to_string()),
                    description: Some("Management Network Interface".to_string()),
                    interface_enabled: Some(true),
                    mac_address: Some(value.bmc_mac_address),
                    uefi_device_path: None,
                }],
            }],
            systems: vec![ComputerSystem {
                id: "Bluefield".to_string(),
                ethernet_interfaces: vec![EthernetInterface {
                    id: Some("oob_net0".to_string()),
                    description: Some("1G DPU OOB network interface".to_string()),
                    interface_enabled: Some(true),
                    mac_address: Some(value.oob_mac_address),
                    uefi_device_path: None,
                }],
                manufacturer: None,
                model: None,
                serial_number: Some(value.serial.clone()),
                attributes: ComputerSystemAttributes {
                    nic_mode: Some(NicMode::Dpu),
                    http_dev1_interface: None,
                    is_infinite_boot_enabled: None,
                },
                pcie_devices: vec![PCIeDevice {
                    odata: OData {
                        odata_id: "odata_id".to_string(),
                        odata_type: "odata_type".to_string(),
                        odata_etag: None,
                        odata_context: None,
                    },
                    description: None,
                    firmware_version: None,
                    id: None,
                    manufacturer: None,
                    gpu_vendor: None,
                    name: None,
                    part_number: Some("900-9D3B6-00CV-AA0".to_string()),
                    serial_number: Some(value.serial.clone()),
                    status: None,
                    slot: None,
                    pcie_functions: None,
                }
                .into()],
                base_mac: Some(value.host_mac_address.to_string().replace(':', "")),
                power_state: PowerState::On,
            }],
            chassis: vec![Chassis {
                id: "Card1".to_string(),
                manufacturer: Some("Nvidia".to_string()),
                model: Some("Bluefield 3 SmartNIC Main Card".to_string()),
                part_number: Some("900-9D3B6-00CV-AA0".to_string()),
                serial_number: Some(value.serial.clone()),
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
            versions: Default::default(),
            model: None,
        }
    }
}

/// Creates a Machine Interface and Machine for a DPU
///
/// Returns the ID of the created machine
pub async fn create_dpu_machine(env: &TestEnv, host_config: &ManagedHostConfig) -> rpc::MachineId {
    let (dpu_machine_id, host_machine_id) =
        create_dpu_machine_in_waiting_for_network_install(env, host_config).await;
    let dpu_rpc_machine_id: rpc::MachineId = dpu_machine_id.to_string().into();

    // Simulate the ForgeAgentControl request of the DPU
    let agent_control_response = forge_agent_control(env, dpu_rpc_machine_id.clone()).await;
    assert_eq!(
        agent_control_response.action,
        rpc::forge_agent_control_response::Action::Noop as i32
    );

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        4,
        &mut txn,
        ManagedHostState::DPUInit {
            dpu_states: crate::model::machine::DpuInitStates {
                states: HashMap::from([(
                    dpu_machine_id.clone(),
                    DpuInitState::WaitingForNetworkConfig,
                )]),
            },
        },
    )
    .await;
    txn.commit().await.unwrap();

    network_configured(env, &dpu_machine_id).await;

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        4,
        &mut txn,
        ManagedHostState::HostInit {
            machine_state: MachineState::EnableIpmiOverLan,
        },
    )
    .await;
    txn.commit().await.unwrap();

    dpu_rpc_machine_id
}

pub async fn create_dpu_machine_in_waiting_for_network_install(
    env: &TestEnv,
    host_config: &ManagedHostConfig,
) -> (MachineId, MachineId) {
    let primary_dpu = host_config.get_and_assert_single_dpu();
    let bmc_machine_interface_id =
        dpu_bmc_discover_dhcp(env, &primary_dpu.bmc_mac_address.to_string()).await;
    // Let's find the IP that we assign to the BMC
    let mut txn = env.pool.begin().await.unwrap();
    let bmc_interface =
        db::machine_interface::find_one(&mut txn, bmc_machine_interface_id.try_into().unwrap())
            .await
            .unwrap();
    let dpu_bmc_ip = bmc_interface.addresses[0];
    txn.rollback().await.unwrap();

    let machine_interface_id =
        dpu_discover_dhcp(env, &primary_dpu.oob_mac_address.to_string()).await;
    let dpu_rpc_machine_id = dpu_discover_machine(env, primary_dpu, machine_interface_id).await;

    let dpu_machine_id = try_parse_machine_id(&dpu_rpc_machine_id).unwrap();

    tracing::debug!("Attempting to create machine inventory");
    create_machine_inventory(env, &dpu_machine_id).await;

    // Simulate the ForgeAgentControl request of the DPU
    let agent_control_response = forge_agent_control(env, dpu_rpc_machine_id.clone()).await;
    assert_eq!(
        agent_control_response.action,
        rpc::forge_agent_control_response::Action::Discovery as i32
    );

    update_dpu_machine_credentials(env, dpu_rpc_machine_id.clone()).await;

    // TODO: This it not really happening in the current version of forge-scout.
    // But it's in the test setup to verify reading back submitted credentials
    // TODO: This IP is allocated by carbide. We need to use the right one
    update_bmc_metadata(
        env,
        dpu_rpc_machine_id.clone(),
        &dpu_bmc_ip.to_string(),
        FIXTURE_DPU_BMC_ADMIN_USER_NAME.to_string(),
        primary_dpu.bmc_mac_address,
        FIXTURE_DPU_BMC_VERSION.to_owned(),
        FIXTURE_DPU_BMC_FIRMWARE_VERSION.to_owned(),
    )
    .await;

    discovery_completed(env, dpu_rpc_machine_id.clone()).await;

    let mut txn = env.pool.begin().await.unwrap();
    let host_machine_id = Machine::find_host_by_dpu_machine_id(&mut txn, &dpu_machine_id)
        .await
        .unwrap()
        .unwrap()
        .id()
        .clone();

    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        4,
        &mut txn,
        ManagedHostState::DPUInit {
            dpu_states: crate::model::machine::DpuInitStates {
                states: HashMap::from([(
                    dpu_machine_id.clone(),
                    DpuInitState::WaitingForNetworkConfig,
                )]),
            },
        },
    )
    .await;

    txn.commit().await.unwrap();

    (dpu_machine_id, host_machine_id)
}

pub async fn create_machine_inventory(env: &TestEnv, machine_id: &MachineId) {
    tracing::debug!("Creating machine inventory for {}", machine_id);
    env.api
        .update_agent_reported_inventory(Request::new(rpc::forge::DpuAgentInventoryReport {
            machine_id: Some(rpc::MachineId {
                id: machine_id.to_string(),
            }),
            inventory: Some(rpc::forge::MachineInventory {
                components: vec![
                    rpc::forge::MachineInventorySoftwareComponent {
                        name: "doca-hbn".to_string(),
                        version: TEST_DOCA_HBN_VERSION.to_string(),
                        url: "nvcr.io/nvidia/doca/".to_string(),
                    },
                    rpc::forge::MachineInventorySoftwareComponent {
                        name: "doca-telemetry".to_string(),
                        version: TEST_DOCA_TELEMETRY_VERSION.to_string(),
                        url: "nvcr.io/nvidia/doca/".to_string(),
                    },
                ],
            }),
        }))
        .await
        .unwrap()
        .into_inner()
}

/// Uses the `discover_dhcp` API to discover a DPU BMC with a certain MAC address
///
/// Returns the created `machine_interface_id`
pub async fn dpu_bmc_discover_dhcp(env: &TestEnv, mac_address: &str) -> rpc::Uuid {
    let response = env
        .api
        .discover_dhcp(Request::new(DhcpDiscovery {
            mac_address: mac_address.to_string(),
            relay_address: FIXTURE_DHCP_RELAY_ADDRESS.to_string(),
            vendor_string: Some("NVIDIA/BF/BMC".to_string()),
            link_address: None,
            circuit_id: None,
            remote_id: None,
        }))
        .await
        .unwrap()
        .into_inner();
    response
        .machine_interface_id
        .expect("machine_interface_id must be set")
}

/// Uses the `discover_dhcp` API to discover a DPU with a certain MAC address
///
/// Returns the created `machine_interface_id`
pub async fn dpu_discover_dhcp(env: &TestEnv, mac_address: &str) -> rpc::Uuid {
    let response = env
        .api
        .discover_dhcp(Request::new(DhcpDiscovery {
            mac_address: mac_address.to_string(),
            relay_address: FIXTURE_DHCP_RELAY_ADDRESS.to_string(),
            vendor_string: None,
            link_address: None,
            circuit_id: None,
            remote_id: None,
        }))
        .await
        .unwrap()
        .into_inner();
    response
        .machine_interface_id
        .expect("machine_interface_id must be set")
}

/// Emulates DPU Machine Discovery (submitting hardware information) for the
/// DPU that uses a certain `machine_interface_id`
pub async fn dpu_discover_machine(
    env: &TestEnv,
    dpu_config: &DpuConfig,
    machine_interface_id: rpc::Uuid,
) -> rpc::MachineId {
    let response = env
        .api
        .discover_machine(Request::new(MachineDiscoveryInfo {
            machine_interface_id: Some(machine_interface_id),
            discovery_data: Some(DiscoveryData::Info(
                DiscoveryInfo::try_from(HardwareInfo::from(dpu_config)).unwrap(),
            )),
            create_machine: true,
        }))
        .await
        .unwrap()
        .into_inner();

    response.machine_id.expect("machine_id must be set")
}

/// Emulates the `UpdateMachineCredentials` request of a DPU
pub async fn update_dpu_machine_credentials(env: &TestEnv, dpu_machine_id: rpc::MachineId) {
    let _response = env
        .api
        .update_machine_credentials(Request::new(MachineCredentialsUpdateRequest {
            machine_id: Some(dpu_machine_id),
            mac_address: None,
            credentials: vec![
                Credentials {
                    user: FIXTURE_DPU_SSH_USERNAME.to_string(),
                    password: FIXTURE_DPU_SSH_PASSWORD.to_string(),
                    credential_purpose: CredentialPurpose::LoginUser as i32,
                },
                Credentials {
                    user: FIXTURE_DPU_HBN_USERNAME.to_string(),
                    password: FIXTURE_DPU_HBN_PASSWORD.to_string(),
                    credential_purpose: CredentialPurpose::Hbn as i32,
                },
            ],
        }))
        .await
        .unwrap()
        .into_inner();
}

// Convenience method for the tests to get a machine's loopback IP
pub async fn loopback_ip(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    dpu_machine_id: &MachineId,
) -> IpAddr {
    let dpu = Machine::find_one(txn, dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    IpAddr::V4(dpu.loopback_ip().unwrap())
}
