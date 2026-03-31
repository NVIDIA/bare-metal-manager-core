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

use std::borrow::Cow;
use std::sync::Arc;

use rpc::machine_discovery::{BlockDevice, CpuInfo, DiscoveryInfo, DmiData, NvmeDevice};
use serde_json::json;
use utils::models::arch::CpuArchitecture;

use crate::{PowerControl, hw, redfish};

pub struct WiwynnGB200Nvl<'a> {
    pub system_serial_number: Cow<'a, str>,
    pub chassis_serial_number: Cow<'a, str>,
    pub compute_board: [hw::nvidia_gb200::BiancaBoard<'a>; 2],
    pub dpu1: hw::bluefield3::Bluefield3<'a>,
    pub dpu2: hw::bluefield3::Bluefield3<'a>,
    pub topology: hw::nvidia_gbx00::Topology,
    pub io_board: [hw::nvidia_gb200::IoBoard<'a>; 2],
}

impl WiwynnGB200Nvl<'_> {
    fn sensor_layout() -> redfish::sensor::Layout {
        redfish::sensor::Layout {
            temperature: 40,
            fan: 10,
            power: 10,
            current: 10,
            leak: 4,
        }
    }

    pub fn manager_config(&self) -> redfish::manager::Config {
        redfish::manager::Config {
            managers: vec![
                redfish::manager::SingleConfig {
                    id: "BMC_0",
                    eth_interfaces: Some(vec![]), // TODO: eth0 / eth1 / hmcusb0 / hostusb0
                    host_interfaces: Some(vec![
                        redfish::host_interface::builder(
                            &redfish::host_interface::manager_resource("BMC_0", "hostusb0"),
                        )
                        .interface_enabled(true)
                        .build(),
                    ]),
                    firmware_version: Some("25.06-2_NV_WW_02"),
                    oem: None,
                },
                redfish::manager::SingleConfig {
                    id: "HGX_BMC_0",
                    eth_interfaces: Some(vec![]), // TODO: usb0
                    host_interfaces: None,
                    firmware_version: Some("GB200Nvl-25.06-A"),
                    oem: None,
                },
            ],
        }
    }

    pub fn system_config(&self, pc: Arc<dyn PowerControl>) -> redfish::computer_system::Config {
        let system_id = "System_0";
        let power_control = Some(pc);
        let serial_number = Some(self.system_serial_number.to_string().into());
        let boot_opt_builder = |id: &str| {
            redfish::boot_option::builder(&redfish::boot_option::resource(system_id, id))
                .boot_option_reference(id)
        };
        let boot_options = [
            boot_opt_builder("Boot0020")
                .display_name("Ubuntu")
                .uefi_device_path("HD(1,GPT,C07AA982-7D30-4663-9538-776771BBED85,0x800,0x219800)/\\EFI\\ubuntu\\shimaa64.efi")
                .build()
        ].into_iter().chain([&self.dpu1, &self.dpu2].into_iter().enumerate().map(|(index, dpu)| {
            let mac = dpu.host_mac_address.to_string().replace(":", "").to_uppercase();
            let display_name = format!("UEFI HTTPv4 (MAC:{mac})");
            boot_opt_builder(&format!("Boot{index:04X}"))
                .display_name(&display_name)
                .uefi_device_path(&format!("MAC({mac},0x1)/IPv4(0.0.0.0,0x0,DHCP,0.0.0.0,0.0.0.0,0.0.0.0)/Uri()"))
                .build()
        })).collect();

        redfish::computer_system::Config {
            systems: vec![
                redfish::computer_system::SingleSystemConfig {
                    id: system_id.into(),
                    manufacturer: Some("WIWYNN".into()),
                    model: Some("GB200 NVL".into()),
                    eth_interfaces: None,
                    serial_number,
                    boot_order_mode: redfish::computer_system::BootOrderMode::ViaSettings,
                    power_control,
                    chassis: vec!["BMC_0".into()],
                    boot_options: Some(boot_options),
                    bios_mode: redfish::computer_system::BiosMode::Generic,
                    oem: redfish::computer_system::Oem::Generic,
                    base_bios: Some(
                        redfish::bios::builder(&redfish::bios::resource(system_id))
                            .attributes(json!({
                                "EmbeddedUefiShell": "Enabled",
                            }))
                            .build(),
                    ),
                    log_services: None,
                    storage: None,
                    secure_boot_available: true,
                },
                redfish::computer_system::SingleSystemConfig {
                    id: "HGX_Baseboard_0".into(),
                    manufacturer: Some("NVIDIA".into()),
                    model: Some("GB200 NVL".into()),
                    chassis: vec!["HGX_Chassis_0".into()],
                    eth_interfaces: None,
                    power_control: None,
                    boot_options: None,
                    serial_number: None,
                    boot_order_mode: redfish::computer_system::BootOrderMode::Generic,
                    oem: redfish::computer_system::Oem::Generic,
                    bios_mode: redfish::computer_system::BiosMode::Generic,
                    base_bios: None,
                    log_services: None,
                    storage: None,
                    secure_boot_available: false,
                },
            ],
        }
    }

    pub fn chassis_config(&self) -> redfish::chassis::ChassisConfig {
        let dpu_chassis = |chassis_id: &'static str, bf3: &hw::bluefield3::Bluefield3<'_>| {
            let nic = bf3.host_nic();
            let network_adapters = Some(vec![
                redfish::network_adapter::builder_from_nic(
                    &redfish::network_adapter::chassis_resource(chassis_id, chassis_id),
                    &nic,
                )
                .status(redfish::resource::Status::Ok)
                .build(),
            ]);

            redfish::chassis::SingleChassisConfig {
                id: chassis_id.into(),
                chassis_type: "Card".into(),
                manufacturer: nic.manufacturer,
                part_number: nic.part_number,
                model: Some("GB200 NVL".into()),
                serial_number: None,
                network_adapters,
                pcie_devices: Some(vec![]),
                sensors: None,
                assembly: None,
                oem: None,
            }
        };
        redfish::chassis::ChassisConfig {
            chassis: std::iter::once(redfish::chassis::SingleChassisConfig {
                id: "BMC_0".into(),
                chassis_type: "Module".into(),
                manufacturer: Some("WIWYNN".into()),
                part_number: Some("B81.11810.0005".into()),
                model: Some("GB200 NVL".into()),
                serial_number: None,
                network_adapters: None,
                pcie_devices: Some(vec![]),
                sensors: None,
                assembly: None,
                oem: None,
            })
            .chain(std::iter::once(redfish::chassis::SingleChassisConfig {
                id: "Chassis_0".into(),
                chassis_type: "RackMount".into(),
                manufacturer: Some("NVIDIA".into()),
                part_number: Some("B81.11810.000D".into()),
                model: Some("GB200 NVL".into()),
                serial_number: None,
                network_adapters: None,
                pcie_devices: None,
                sensors: Some(redfish::sensor::generate_chassis_sensors(
                    "Chassis_0",
                    Self::sensor_layout(),
                )),
                assembly: Some(
                    redfish::assembly::builder(&redfish::assembly::chassis_resource("Chassis_0"))
                        .add_data(
                            redfish::assembly::data_builder("0".into())
                                .serial_number(&self.chassis_serial_number)
                                .build(),
                        )
                        .build(),
                ),
                oem: None,
            }))
            .chain((0..4).map(|index| {
                hw::nvidia_gbx00::cbc_chassis(format!("CBC_{index}").into(), &self.topology)
            }))
            .chain(
                [(0, "HGX_CPU_0"), (1, "HGX_CPU_1")]
                    .map(|(index, id)| self.compute_board[index].hgx_cpu_chassis(id.into())),
            )
            .chain(
                [
                    (
                        0,
                        [
                            hw::nvidia_gb200::GpuChassisIds {
                                chassis_id: "HGX_GPU_0".into(),
                                pcie_device_id: "GPU_0".into(),
                            },
                            hw::nvidia_gb200::GpuChassisIds {
                                chassis_id: "HGX_GPU_1".into(),
                                pcie_device_id: "GPU_1".into(),
                            },
                        ],
                    ),
                    (
                        1,
                        [
                            hw::nvidia_gb200::GpuChassisIds {
                                chassis_id: "HGX_GPU_2".into(),
                                pcie_device_id: "GPU_2".into(),
                            },
                            hw::nvidia_gb200::GpuChassisIds {
                                chassis_id: "HGX_GPU_3".into(),
                                pcie_device_id: "GPU_3".into(),
                            },
                        ],
                    ),
                ]
                .into_iter()
                .flat_map(|(index, ids)| self.compute_board[index].hgx_gpu_chassis(ids)),
            )
            .chain(
                self.io_board
                    .iter()
                    .zip(["IO_Board_0", "IO_Board_1"])
                    .map(|(board, id)| board.as_chassis(id.into())),
            )
            .chain(std::iter::once(dpu_chassis(
                "Riser_Slot1_BlueField_3_Card",
                &self.dpu1,
            )))
            .chain(std::iter::once(dpu_chassis(
                "Riser_Slot2_BlueField_3_Card",
                &self.dpu2,
            )))
            .collect(),
        }
    }

    pub fn update_service_config(&self) -> redfish::update_service::UpdateServiceConfig {
        let fw_inv_builder = |id: &str| {
            redfish::software_inventory::builder(
                &redfish::software_inventory::firmware_inventory_resource(id),
            )
        };
        redfish::update_service::UpdateServiceConfig {
            firmware_inventory: [
                // Different examples from real H/W:
                ("FW_BMC_0", "25.06-2_NV_WW_02"),
                ("FW_BMC_1", "    "),
                ("FW_CPLD_0", "0x00 0x0b 0x03 0x04"),
                ("FW_ERoT_AP_CFG_0", "0128"),
                ("NIC_0", "32.47.1026"),
                ("TPM_Firmware", "15.23"),
                ("UEFI", "02.04.12-dde0f655"),
                ("HGX_FW_BMC_0", "GB200Nvl-25.06-A"),
                ("HGX_FW_CPLD_0", "0.22"),
                ("HGX_FW_CPU_0", "00000082"),
                ("HGX_FW_ERoT_BMC_0", "01.04.0031.0000_n04"),
            ]
            .iter()
            .map(|(id, version)| fw_inv_builder(id).version(version).build())
            .collect(),
        }
    }

    pub fn discovery_info(&self) -> DiscoveryInfo {
        DiscoveryInfo {
            network_interfaces: vec![
                self.dpu1.host_nic().discovery_info(0x0603),
                self.dpu2.host_nic().discovery_info(0x1603),
            ],
            infiniband_interfaces: self
                .io_board
                .iter()
                .flat_map(|board| board.discovery_infiniband())
                .collect(),
            cpu_info: vec![CpuInfo {
                model: "Neoverse-V2".into(),
                vendor: "ARM".into(),
                sockets: 2,
                cores: 72,
                threads: 72,
            }],
            block_devices: (0..9)
                .map(|n| BlockDevice {
                    model: "SAMSUNG MZTL63T8HFLT-00AW7".into(),
                    revision: "LDDL4U2Q".into(),
                    serial: format!("BDFAKESERNUM{n}"),
                    device_type: "disk".into(),
                })
                .collect(),
            machine_type: CpuArchitecture::Aarch64.to_string(),
            machine_arch: Some(CpuArchitecture::Aarch64.into()),
            nvme_devices: (0..9)
                .map(|n| NvmeDevice {
                    model: "SAMSUNG MZTL63T8HFLT-00AW7".into(),
                    firmware_rev: "LDDL4U2Q".into(),
                    serial: format!("BDFAKESERNUM{n}"),
                })
                .collect(),
            dmi_data: Some(DmiData {
                board_name: "KINABALU BMC CARD".into(),
                board_version: "PVT".into(),
                bios_version: "00000083".into(),
                bios_date: "20260107".into(),
                product_serial: self.chassis_serial_number.to_string(),
                board_serial: self.chassis_serial_number.to_string(),
                chassis_serial: self.chassis_serial_number.to_string(),
                product_name: "GB200 NVL".into(),
                sys_vendor: "NVIDIA".into(),
            }),
            dpu_info: None,
            gpus: self
                .compute_board
                .iter()
                .flat_map(|board| board.discovery_gpu())
                .collect(),
            memory_devices: self
                .compute_board
                .iter()
                .map(|board| board.discovery_memory())
                .collect(),
            tpm_ek_certificate: None,
            tpm_description: None,
            ..Default::default()
        }
    }
}
