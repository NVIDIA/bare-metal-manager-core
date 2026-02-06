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

use std::iter;
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};

use itertools::Itertools;
use libredfish::{OData, PCIeDevice};
use mac_address::MacAddress;
use model::hardware_info::{HardwareInfo, NetworkInterface, PciDeviceProperties, TpmEkCertificate};
use model::machine::ManagedHostState;
use model::site_explorer::{
    Chassis, ComputerSystem, ComputerSystemAttributes, EndpointExplorationReport, EndpointType,
    EthernetInterface, Inventory, Manager, NetworkAdapter, PowerState, Service, UefiDevicePath,
};

use super::create_random_self_signed_cert;
use crate::tests::common::api_fixtures::dpu::DpuConfig;
use crate::tests::common::api_fixtures::host::X86_INFO_JSON;
use crate::tests::common::{ib_guid_pool, mac_address_pool};

static NEXT_HOST_SERIAL: AtomicU32 = AtomicU32::new(1);
const REQUIRED_IB_GUIDS: usize = 6;

#[derive(Debug, Clone)]
pub enum HardwareInfoTemplate {
    Default,
    Custom(&'static [u8]),
}

/// Describes a Managed Host
#[derive(Debug, Clone)]
pub struct ManagedHostConfig {
    pub serial: String,
    pub bmc_mac_address: MacAddress,
    pub tpm_ek_cert: TpmEkCertificate,
    pub dpus: Vec<DpuConfig>,
    pub non_dpu_macs: Vec<MacAddress>,
    pub expected_state: ManagedHostState,
    pub ib_guids: Vec<String>,
    /// Control whether the test fixture should automatically generate and assign SKU
    /// when machine enters WaitingForSkuAssignment state.
    /// Default: true (maintains backward compatibility)
    pub auto_assign_sku_in_fixture: bool,
    pub hardware_info_template: HardwareInfoTemplate,
}

impl ManagedHostConfig {
    pub fn with_serial(serial: String) -> Self {
        Self {
            serial,
            ..Default::default()
        }
    }

    pub fn with_dpus(dpus: Vec<DpuConfig>) -> Self {
        Self {
            dpus,
            ..Default::default()
        }
    }

    pub fn with_expected_state(expected_state: ManagedHostState) -> Self {
        Self {
            expected_state,
            ..Default::default()
        }
    }

    pub fn with_hardware_info_template(hardware_info_template: HardwareInfoTemplate) -> Self {
        Self {
            hardware_info_template,
            ..Default::default()
        }
    }

    pub fn dhcp_mac_address(&self) -> MacAddress {
        if let Some(dpu) = self.dpus.first() {
            dpu.host_mac_address
        } else if let Some(non_dpu_mac) = self.non_dpu_macs.first() {
            *non_dpu_mac
        } else {
            panic!("No DPUs or non-DPU NICs on MockHost")
        }
    }

    pub fn get_and_assert_single_dpu(&self) -> &DpuConfig {
        let (1, Some(single_dpu)) = (self.dpus.len(), self.dpus.first()) else {
            panic!("Expected a single-DPU host, got {} DPUs", self.dpus.len());
        };
        single_dpu
    }
}

impl Default for ManagedHostConfig {
    fn default() -> Self {
        let random_cert = create_random_self_signed_cert();
        Self {
            serial: format!(
                "VVG1{:05X}",
                NEXT_HOST_SERIAL.fetch_add(1, Ordering::Relaxed)
            ),
            bmc_mac_address: mac_address_pool::HOST_BMC_MAC_ADDRESS_POOL.allocate(),
            tpm_ek_cert: TpmEkCertificate::from(random_cert),
            dpus: vec![DpuConfig::default()],
            non_dpu_macs: vec![mac_address_pool::HOST_NON_DPU_MAC_ADDRESS_POOL.allocate()],
            expected_state: ManagedHostState::Ready,
            // Create 6 IB GUIDs - which is what is required by x86_info.json
            ib_guids: std::iter::repeat_with(|| ib_guid_pool::IB_GUID_POOL.allocate())
                .take(6)
                .collect(),
            auto_assign_sku_in_fixture: true,
            hardware_info_template: HardwareInfoTemplate::Default,
        }
    }
}

impl From<&ManagedHostConfig> for HardwareInfo {
    fn from(config: &ManagedHostConfig) -> Self {
        let mut info =
            serde_json::from_slice::<HardwareInfo>(match config.hardware_info_template {
                HardwareInfoTemplate::Default => X86_INFO_JSON,
                HardwareInfoTemplate::Custom(data) => data,
            })
            .unwrap();
        info.tpm_ek_certificate = Some(config.tpm_ek_cert.clone());
        info.dmi_data.as_mut().unwrap().product_serial = config.serial.clone();
        info.dmi_data.as_mut().unwrap().chassis_serial = config.serial.clone();
        info.network_interfaces = config
            .dpus
            .iter()
            .map(|d| NetworkInterface {
                mac_address: d.host_mac_address,
                pci_properties: Some(PciDeviceProperties {
                    vendor: "mellanox".to_string(),
                    device: "DPU1".to_string(),
                    path: "/x/y/z".to_string(),
                    numa_node: 1,
                    description: None,
                    slot: None,
                }),
            })
            .chain(config.non_dpu_macs.iter().map(|m| NetworkInterface {
                mac_address: *m,
                pci_properties: None,
            }))
            .collect();
        // Generate a unique GUID for each InfiniBand interface in the template
        // For the moment this only supports hosts with a fixed amount of 6 interfaces
        assert_eq!(
            config.ib_guids.len(),
            REQUIRED_IB_GUIDS,
            "The amount of {} IB GUIDs passed to the config does not match the {} GUIDs required by the test_data template",
            config.ib_guids.len(),
            REQUIRED_IB_GUIDS
        );
        for (ib_interface, guid) in info
            .infiniband_interfaces
            .iter_mut()
            .zip(config.ib_guids.iter())
        {
            ib_interface.guid = guid.clone();
        }
        info
    }
}

impl From<ManagedHostConfig> for EndpointExplorationReport {
    fn from(value: ManagedHostConfig) -> Self {
        let next_nic_index = value.dpus.len() + 1;

        let network_adapters = value
            .dpus
            .iter()
            .enumerate()
            .map(|(index, dpu)| NetworkAdapter {
                id: format!("slot-{}", index + 1),
                manufacturer: Some("MLNX".to_string()),
                model: Some("BlueField-3 P-Series DPU 200GbE/".to_string()),
                part_number: Some("900-9D3B6-00CV-A".to_string()),
                serial_number: Some(dpu.serial.clone()),
            })
            .chain(iter::once(NetworkAdapter {
                id: format!("slot-{next_nic_index}"),
                manufacturer: Some("Broadcom Limited".to_string()),
                model: Some("5720".to_string()),
                part_number: Some("SN30L21970".to_string()),
                serial_number: Some("L2NV97J018G".to_string()),
            }))
            .collect();

        let pcie_devices = value
            .dpus
            .iter()
            .map(|dpu| PCIeDevice {
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
                part_number: Some("900-9D3B6-00CV-A".to_string()),
                serial_number: Some(dpu.serial.clone()),
                status: None,
                slot: None,
                pcie_functions: None,
            })
            .collect::<Vec<_>>();

        let systems_ethernet_interfaces = value
            .non_dpu_macs
            .iter()
            .enumerate()
            .map(|(index, mac)| {
                let port = index + 1;
                EthernetInterface {
                    id: Some(format!("NIC.Embedded.{port}-1-1")),
                    description: Some(format!("Embedded NIC 1 Port {port} Partition 1")),
                    interface_enabled: Some(true),
                    mac_address: Some(*mac),
                    uefi_device_path: None,
                }
            })
            .chain(value.dpus.iter().enumerate().map(|(index, dpu)| {
                let slot = index + 5; // DPUs start with 5....
                EthernetInterface {
                    id: Some(format!("NIC.Slot.{slot}-1")),
                    description: Some(format!("NIC in Slot {slot} Port 1")),
                    interface_enabled: Some(true),
                    mac_address: Some(dpu.host_mac_address),
                    uefi_device_path: Some(
                        dpu.override_hosts_uefi_device_path.clone().unwrap_or(
                            UefiDevicePath::from_str(&format!(
                                "PciRoot(0x8)/Pci(0x2,0xa)/Pci(0x0,0x{:x})/MAC({},0x1)",
                                index + 1,
                                dpu.host_mac_address.to_string().replace(':', ""),
                            ))
                            .unwrap(),
                        ),
                    ),
                }
            }))
            .collect_vec();

        Self {
            endpoint_type: EndpointType::Bmc,
            last_exploration_error: None,
            last_exploration_latency: None,
            vendor: Some(bmc_vendor::BMCVendor::Dell),
            managers: vec![Manager {
                id: "iDRAC.Embedded.1".to_string(),
                ethernet_interfaces: vec![EthernetInterface {
                    id: Some("NIC.1".to_string()),
                    description: Some("Management Network Interface".to_string()),
                    interface_enabled: Some(true),
                    mac_address: Some(value.bmc_mac_address),
                    uefi_device_path: None,
                }],
            }],
            systems: vec![ComputerSystem {
                id: "System.Embedded.1".to_string(),
                manufacturer: Some("Dell Inc.".to_string()),
                model: Some("PowerEdge R750".to_string()),
                serial_number: Some(value.serial.clone()),
                ethernet_interfaces: systems_ethernet_interfaces,
                attributes: ComputerSystemAttributes::default(),
                pcie_devices: pcie_devices.into_iter().map(Into::into).collect(),
                base_mac: None,
                power_state: PowerState::On,
                sku: None,
                boot_order: None,
            }],
            chassis: vec![Chassis {
                id: "System.Embedded.1".to_string(),
                manufacturer: Some("Dell Inc.".to_string()),
                model: Some("PowerEdge R750".to_string()),
                part_number: Some("SB27A42862".to_string()),
                serial_number: Some(value.serial),
                network_adapters,
                compute_tray_index: None,
                physical_slot_number: None,
                revision_id: None,
                topology_id: None,
            }],
            service: vec![Service {
                id: "FirmwareInventory".to_string(),
                inventories: vec![
                    Inventory {
                        id: "Installed-__iDRACz".to_string(),
                        description: Some("The information of BMC (Primary) firmware.".to_string()),
                        version: Some("5.10.20".to_string()),
                        release_date: None,
                    },
                    Inventory {
                        id: "Current-159-1.13.2__BIOS.Setup.1-1".to_string(),
                        description: Some("The information of Firmware firmware.".to_string()),
                        version: Some("1.12.0".to_string()),
                        release_date: None,
                    },
                ],
            }],
            machine_id: None,
            versions: Default::default(),
            model: None,
            machine_setup_status: None,
            secure_boot_status: None,
            lockdown_status: None,
            power_shelf_id: None,
            switch_id: None,
            physical_slot_number: None,
            compute_tray_index: None,
            revision_id: None,
            topology_id: None,
        }
    }
}
