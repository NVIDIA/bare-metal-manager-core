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

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};

use carbide_uuid::machine::{MachineId, MachineInterfaceId};
use libredfish::model::oem::nvidia_dpu::NicMode;
use libredfish::{OData, PCIeDevice};
use mac_address::MacAddress;
use model::hardware_info::HardwareInfo;
use model::machine::machine_search_config::MachineSearchConfig;
use model::site_explorer::{
    Chassis, ComputerSystem, ComputerSystemAttributes, EndpointExplorationError,
    EndpointExplorationReport, EndpointType, EthernetInterface, Inventory, Manager, PowerState,
    Service, UefiDevicePath,
};
use rpc::forge::forge_server::Forge;
use rpc::{DiscoveryData, DiscoveryInfo, MachineDiscoveryInfo};
use sqlx::PgConnection;
use tonic::Request;

use super::site_explorer;
use crate::cfg::file::DpuConfig as InitialDpuConfig;
use crate::tests::common::api_fixtures::managed_host::{HardwareInfoTemplate, ManagedHostConfig};
use crate::tests::common::api_fixtures::{FIXTURE_DHCP_RELAY_ADDRESS, TestEnv, TestManagedHost};
use crate::tests::common::mac_address_pool;
use crate::tests::common::rpc_builder::DhcpDiscovery;

/// The version identifier that is used by dpu-agent in unit-tests
pub const TEST_DPU_AGENT_VERSION: &str = "test";

/// The version of HBN reported in unit-tests
pub const TEST_DOCA_HBN_VERSION: &str = "1.5.0-doca2.2.0";
/// The version of doca-telemetry reported in unit-tests
pub const TEST_DOCA_TELEMETRY_VERSION: &str = "1.14.2-doca2.2.0";

pub const DPU_INFO_JSON: &[u8] =
    include_bytes!("../../../../../api-model/src/hardware_info/test_data/dpu_info.json");

pub const DPU_BF3_INFO_JSON: &[u8] =
    include_bytes!("../../../../../api-model/src/hardware_info/test_data/dpu_bf3_info.json");

static NEXT_DPU_SERIAL: AtomicU32 = AtomicU32::new(1);

#[derive(Clone, Debug)]
pub struct DpuConfig {
    pub serial: String,
    pub host_mac_address: MacAddress,
    pub oob_mac_address: MacAddress,
    pub bmc_mac_address: MacAddress,
    pub last_exploration_error: Option<EndpointExplorationError>,
    pub override_hosts_uefi_device_path: Option<UefiDevicePath>,
    pub hardware_info_template: HardwareInfoTemplate,
}

impl DpuConfig {
    pub fn with_serial(serial: String) -> Self {
        Self {
            serial,
            ..Default::default()
        }
    }

    pub fn with_hardware_info_template(hardware_info_template: HardwareInfoTemplate) -> Self {
        Self {
            hardware_info_template,
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
            hardware_info_template: HardwareInfoTemplate::Default,
        }
    }
}

impl From<&DpuConfig> for HardwareInfo {
    fn from(value: &DpuConfig) -> Self {
        let template = match value.hardware_info_template {
            HardwareInfoTemplate::Default => DPU_INFO_JSON,
            HardwareInfoTemplate::Custom(data) => data,
        };
        let mut info = serde_json::from_slice::<HardwareInfo>(template).unwrap();
        info.dpu_info.as_mut().unwrap().factory_mac_address = value.host_mac_address.to_string();
        info.dpu_info.as_mut().unwrap().firmware_version = "24.42.1000".to_string();
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
                    is_infinite_boot_enabled: None,
                },
                pcie_devices: vec![
                    PCIeDevice {
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
                    .into(),
                ],
                base_mac: Some(value.host_mac_address.to_string().replace(':', "")),
                power_state: PowerState::On,
                sku: None,
                boot_order: None,
            }],
            chassis: vec![Chassis {
                id: "Card1".to_string(),
                manufacturer: Some("Nvidia".to_string()),
                model: Some("Bluefield 3 SmartNIC Main Card".to_string()),
                part_number: Some("900-9D3B6-00CV-AA0".to_string()),
                serial_number: Some(value.serial),
                network_adapters: vec![],
                compute_tray_index: None,
                physical_slot_number: None,
                revision_id: None,
                topology_id: None,
            }],
            service: vec![Service {
                id: "FirmwareInventory".to_string(),
                inventories: vec![
                    Inventory {
                        id: "DPU_NIC".to_string(),
                        description: Some("Host image".to_string()),
                        version: Some("32.42.1000".to_string()),
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
                        version: Some(
                            InitialDpuConfig::default()
                                .find_bf3_entry()
                                .unwrap()
                                .version
                                .clone(),
                        ),
                        release_date: None,
                    },
                    Inventory {
                        id: "DPU_OFED".to_string(),
                        description: Some("Host image".to_string()),
                        version: Some("MLNX_OFED_LINUX-23.10-1.1.8".to_string()),
                        release_date: None,
                    },
                    Inventory {
                        id: "Bluefield_FW_ERoT".to_string(),
                        description: Some("Host image".to_string()),
                        version: Some("00.02.0182.0000_n02".to_string()),
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
            component_fetch_times: HashMap::new(),
            versions: Default::default(),
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
        }
    }
}

/// Creates a Machine Interface and Machine for a DPU
///
/// Returns the ID of the created machine
pub async fn create_dpu_machine(
    env: &TestEnv,
    host_config: &ManagedHostConfig,
) -> carbide_uuid::machine::MachineId {
    site_explorer::new_dpu(env, host_config.clone())
        .await
        .unwrap()
}

pub async fn create_dpu_machine_in_waiting_for_network_install(
    env: &TestEnv,
    host_config: &ManagedHostConfig,
) -> TestManagedHost {
    site_explorer::new_dpu_in_network_install(env, host_config.clone())
        .await
        .unwrap()
}

pub async fn create_machine_inventory(env: &TestEnv, machine_id: MachineId) {
    tracing::debug!("Creating machine inventory for {}", machine_id);
    env.api
        .update_agent_reported_inventory(Request::new(rpc::forge::DpuAgentInventoryReport {
            machine_id: Some(machine_id),
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

/// Uses the `discover_dhcp` API to discover a DPU with a certain MAC address
///
/// Returns the created `machine_interface_id`
pub async fn dpu_discover_dhcp(env: &TestEnv, mac_address: &str) -> MachineInterfaceId {
    let response = env
        .api
        .discover_dhcp(
            DhcpDiscovery::builder(mac_address, FIXTURE_DHCP_RELAY_ADDRESS).tonic_request(),
        )
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
    machine_interface_id: MachineInterfaceId,
) -> carbide_uuid::machine::MachineId {
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

// Convenience method for the tests to get a machine's loopback IP
pub async fn loopback_ip(txn: &mut PgConnection, dpu_machine_id: &MachineId) -> IpAddr {
    let dpu = db::machine::find_one(txn, dpu_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    IpAddr::V4(dpu.network_config.loopback_ip.unwrap())
}
