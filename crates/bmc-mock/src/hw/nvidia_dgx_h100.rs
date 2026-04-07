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

use mac_address::MacAddress;
use rpc::machine_discovery::{CpuInfo, Gpu, InfinibandInterface, MemoryDevice};
use rpc::{BlockDevice, DiscoveryInfo, DmiData, NetworkInterface, NvmeDevice, PciDeviceProperties};
use serde_json::json;
use utils::models::arch::CpuArchitecture;

use crate::json::JsonExt;
use crate::{BootOptionKind, Callbacks, hw, redfish};

pub struct NvidiaDgxH100<'a> {
    pub dgx_system_serial_number: Cow<'a, str>,
    pub dgx_chassis_serial_number: Cow<'a, str>,
    pub ib_nics: [hw::nic_nvidia_cx7::NicNvidiaCx7B<'a>; 2],
    pub mgmt_nic: hw::nic_intel_x550::NicIntelX550,
    pub dpu: hw::bluefield3::Bluefield3<'a>,
    pub storage_nic0: hw::nic_nvidia_cx7::NicNvidiaCx7A<'a>,
    pub storage_nic1: hw::nic_intel_e810::NicIntelE810,
    pub gpu_serial: [Cow<'a, str>; 8],
    pub bmc_mac_address_eth0: MacAddress,
    pub bmc_mac_address_usb0: MacAddress,
    pub hgx_bmc_mac_address_usb0: MacAddress,
}

impl NvidiaDgxH100<'_> {
    pub fn manager_config(&self) -> redfish::manager::Config {
        let bmc_manager_id = "BMC";
        let bmc_eth_builder = |eth| {
            redfish::ethernet_interface::builder(&redfish::ethernet_interface::manager_resource(
                bmc_manager_id,
                eth,
            ))
        };
        redfish::manager::Config {
            managers: vec![
                redfish::manager::SingleConfig {
                    id: bmc_manager_id,
                    eth_interfaces: Some(vec![
                        bmc_eth_builder("eth0")
                            .mac_address(self.bmc_mac_address_eth0)
                            .interface_enabled(true)
                            .build(),
                        bmc_eth_builder("usb0")
                            .mac_address(self.bmc_mac_address_usb0)
                            .interface_enabled(true)
                            .build(),
                    ]),
                    host_interfaces: Some(vec![
                        redfish::host_interface::builder(
                            &redfish::host_interface::manager_resource(bmc_manager_id, "Self"),
                        )
                        .interface_enabled(true)
                        .build(),
                    ]),
                    firmware_version: Some("25.02.12"),
                    oem: None,
                },
                redfish::manager::SingleConfig {
                    id: "HGX_BMC_0",
                    eth_interfaces: Some(vec![
                        redfish::ethernet_interface::builder(
                            &redfish::ethernet_interface::manager_resource("HGX_BMC_0", "usb0"),
                        )
                        .mac_address(self.hgx_bmc_mac_address_usb0)
                        .interface_enabled(true)
                        .build(),
                    ]),
                    host_interfaces: None,
                    firmware_version: Some("HGX-22.10-1-rc67"),
                    oem: None,
                },
                redfish::manager::SingleConfig {
                    id: "HGX_FabricManager_0",
                    eth_interfaces: None,
                    host_interfaces: None,
                    firmware_version: None,
                    oem: None,
                },
            ],
        }
    }

    pub fn system_config(&self, callbacks: Arc<dyn Callbacks>) -> redfish::computer_system::Config {
        let system_id = "DGX";
        let callbacks = Some(callbacks);
        let storage_nic0_ports = self.storage_nic0.ethernet_nics();
        let storage_nic1_ports = self.storage_nic1.ethernet_nics();

        let eth_interfaces = Some(
            [
                &self.mgmt_nic.to_nic(),
                &self.dpu.host_nic_h100_variant(),
                &storage_nic0_ports[0],
                &storage_nic0_ports[1],
                &storage_nic1_ports[0],
                &storage_nic1_ports[1],
            ]
            .iter()
            .enumerate()
            .map(|(index, nic)| {
                redfish::ethernet_interface::builder(&redfish::ethernet_interface::system_resource(
                    system_id,
                    &format!("EthernetInterface{index}"),
                ))
                .mac_address(nic.mac_address)
                .interface_enabled(false)
                .build()
            })
            .collect(),
        );

        let boot_options = [
            &[self.mgmt_nic.to_nic()] as &[hw::nic::Nic],
            &self.storage_nic0.ethernet_nics(),
            &self.storage_nic1.ethernet_nics(),
            &[self.dpu.host_nic_h100_variant()],
        ]
        .into_iter()
        .flatten()
        .enumerate()
        .map(|(n, nic)| {
            let id = format!("{:04X}", n + 10); // Starting with 000A
            // TODO should be taken from NIC:
            let pci_path = "PciRoot(0x0)/Pci(0x10,0x0)/Pci(0x0,0x0)";
            redfish::boot_option::builder(
                &redfish::boot_option::resource(system_id, &id),
                BootOptionKind::Network,
            )
            .boot_option_reference(&format!("Boot{id}"))
            // Real DisplayName: "UEFI P0: HTTP IPv4 Nvidia Network Adapter - 94:6D:AE:00:00:00"
            .display_name(&format!("UEFI Pn: HTTP IPv4 - {}", nic.mac_address))
            .alias("UefiHttp")
            .uefi_device_path(&format!(
                "{pci_path}/MAC({},0x1)/IPv4(0.0.0.0,0x0,DHCP,0.0.0.0,0.0.0.0,0.0.0.0)/Uri()",
                nic.mac_address.to_string().replace(":", "")
            ))
            // libredfish model requires @odata.etag field.
            .odata_etag("MakeLibRedfishHappy")
            .build()
        })
        .chain(std::iter::once(
            redfish::boot_option::builder(
                &redfish::boot_option::resource(system_id, "0030"),
                BootOptionKind::Disk,
            )
            .boot_option_reference("Boot0030")
            .display_name("UEFI OS")
            .build(),
        ))
        .collect();

        redfish::computer_system::Config {
            systems: vec![
                redfish::computer_system::SingleSystemConfig {
                    id: system_id.into(),
                    manufacturer: Some("NVIDIA".into()),
                    model: Some("DGXH100".into()),
                    eth_interfaces,
                    serial_number: Some(self.dgx_system_serial_number.to_string().into()),
                    boot_order_mode: redfish::computer_system::BootOrderMode::ViaSettings,
                    callbacks,
                    chassis: vec!["BMC".into()],
                    boot_options: Some(boot_options),
                    bios_mode: redfish::computer_system::BiosMode::Generic,
                    oem: redfish::computer_system::Oem::Generic,
                    base_bios: Some(base_bios(system_id)),
                    log_services: None,
                    storage: None,
                    secure_boot_available: true,
                },
                redfish::computer_system::SingleSystemConfig {
                    id: "HGX_Baseboard_0".into(),
                    manufacturer: Some("NVIDIA".into()),
                    model: None,
                    chassis: vec!["HGX_BMC_0".into()],
                    eth_interfaces: None,
                    callbacks: None,
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
        let dgx_chassis_id = "DGX";
        let net_adapter_builder = |id: &str| {
            redfish::network_adapter::builder(&redfish::network_adapter::chassis_resource(
                dgx_chassis_id,
                id,
            ))
        };
        let ib_mapping = [["10", "11", "7", "9"], ["2", "4", "5", "6"]];
        let ib_nics = self.ib_nics.each_ref().map(|nic| nic.ib_nics());
        let mut dgx_network_adapters = [
            ("0", net_adapter_builder("DevType7_NIC0").build()),
            (
                "1",
                redfish::network_adapter::builder_from_nic(
                    &redfish::network_adapter::chassis_resource(dgx_chassis_id, "DevType7_NIC1"),
                    &self.dpu.host_nic_h100_variant(),
                )
                .build(),
            ),
            (
                "3",
                redfish::network_adapter::builder_from_nic(
                    &redfish::network_adapter::chassis_resource(dgx_chassis_id, "DevType7_NIC3"),
                    &self.storage_nic0.ethernet_nics()[0],
                )
                .build(),
            ),
            (
                "8",
                redfish::network_adapter::builder_from_nic(
                    &redfish::network_adapter::chassis_resource(dgx_chassis_id, "DevType7_NIC8"),
                    &self.storage_nic1.ethernet_nics()[0],
                )
                .build(),
            ),
        ]
        .into_iter()
        .chain(ib_nics.into_iter().enumerate().flat_map(|(n1, nics)| {
            nics.into_iter().enumerate().map(move |(n2, nic)| {
                let index = ib_mapping[n1][n2];
                (
                    index,
                    redfish::network_adapter::builder_from_nic(
                        &redfish::network_adapter::chassis_resource(
                            dgx_chassis_id,
                            &format!("DevType7_NIC{index}"),
                        ),
                        &nic,
                    )
                    .build(),
                )
            })
        }))
        .collect::<Vec<_>>();
        dgx_network_adapters.sort_by_key(|v| v.0);
        let dgx_network_adapters = dgx_network_adapters.into_iter().map(|v| v.1).collect();
        redfish::chassis::ChassisConfig {
            chassis: [
                redfish::chassis::SingleChassisConfig {
                    id: Cow::Borrowed("CPUBaseboard"),
                    chassis_type: "Component".into(),
                    manufacturer: Some("NVIDIA".into()),
                    part_number: Some("965-24387-0002-000".into()),
                    model: Some("DGXH100".into()),
                    serial_number: Some(self.dgx_system_serial_number.to_string().into()),
                    network_adapters: Some(vec![]),
                    pcie_devices: None,
                    sensors: Some(redfish::sensor::generate_chassis_sensors(
                        "CPUBaseboard",
                        redfish::sensor::Layout {
                            temperature: 120,
                            ..Default::default()
                        },
                    )),
                    assembly: None,
                    oem: None,
                },
                redfish::chassis::SingleChassisConfig {
                    id: dgx_chassis_id.into(),
                    chassis_type: "Other".into(),
                    manufacturer: Some("NVIDIA".into()),
                    part_number: Some("965-24387-0002-000".into()),
                    model: Some("DGXH100".into()),
                    serial_number: Some(self.dgx_chassis_serial_number.to_string().into()),
                    network_adapters: Some(dgx_network_adapters),
                    pcie_devices: Some(
                        (0..133)
                            .map(|n| {
                                redfish::pcie_device::builder(
                                    &redfish::pcie_device::chassis_resource(
                                        dgx_chassis_id,
                                        &format!("00_00_{n:02X}"),
                                    ),
                                )
                                .build()
                            })
                            .collect(),
                    ),
                    sensors: Some(redfish::sensor::generate_chassis_sensors(
                        dgx_chassis_id,
                        redfish::sensor::Layout {
                            temperature: 112 + 8, // TEMP_* + TLIMIT_*
                            fan: 36,              // FAN_*
                            power: 47,            // PWR_*
                            current: 3,           // AMP_*
                            leak: 17,             // VOLT_*
                                                  // TOTAL: 223 of 253
                                                  // Omitted: 29
                                                  //     ENERGY_* = 12,
                                                  //     HMCReady,
                                                  //     OVERT_* = 2,
                                                  //     RST_GB1_GPU,
                                                  //     SEL_FULLNESS,
                                                  //     STATUS_* = 12,
                                                  //     WATCHDOG2
                        },
                    )),
                    assembly: None,
                    oem: None,
                },
            ]
            .into_iter()
            .chain((1..=8).map(|index| hgx_gpu_sxm_chassis(index, &self.gpu_serial[index - 1])))
            .collect(),
        }
    }

    pub fn update_service_config(&self) -> redfish::update_service::UpdateServiceConfig {
        redfish::update_service::UpdateServiceConfig {
            firmware_inventory: [
                // version required carbide to pass ingestion test in site explorer.
                ("CPLDMB_0", "0.2.1.9"),
                // This one is needed for libredfish to setup lockdown
                ("HostBIOS_0", "01.05.03"),
                // This one is needed for libredfish to setup lockdown
                ("HostBMC_0", "24.09.17"),
            ]
            .iter()
            .map(|(id, version)| {
                redfish::software_inventory::builder(
                    &redfish::software_inventory::firmware_inventory_resource(id),
                )
                .version(version)
                .build()
            })
            .collect(),
        }
    }

    pub fn discovery_info(&self) -> DiscoveryInfo {
        DiscoveryInfo {
            network_interfaces: self.discovery_info_network_interfaces(),
            infiniband_interfaces: self.discovery_info_ib_interfaces(),
            cpu_info: vec![CpuInfo {
                model: "Intel(R) Xeon(R) Platinum 8480CL".into(),
                vendor: "GenuineIntel".into(),
                sockets: 2,
                cores: 56,
                threads: 112,
            }],
            block_devices: (0..2)
                .map(|n| BlockDevice {
                    model: "Micron_7450_MTFDKBG1T9TFR".into(),
                    revision: "E2MU200".into(),
                    serial: format!("MicronFAKESERNUM{n}"),
                    device_type: "disk".into(),
                })
                .chain((0..8).map(|n| BlockDevice {
                    model: "KCM6DRUL3T84".into(),
                    revision: "0107".into(),
                    serial: format!("KCMFAKESERNUM{n}"),
                    device_type: "disk".into(),
                }))
                .collect(),
            machine_type: CpuArchitecture::X86_64.to_string(),
            machine_arch: Some(CpuArchitecture::X86_64.into()),
            nvme_devices: (0..2)
                .map(|n| NvmeDevice {
                    model: "Micron_7450_MTFDKBG1T9TFR".into(),
                    firmware_rev: "E2MU200".into(),
                    serial: format!("MicronFAKESERNUM{n}"),
                })
                .chain((0..8).map(|n| NvmeDevice {
                    model: "KCM6DRUL3T84".into(),
                    firmware_rev: "0107".into(),
                    serial: format!("KCMFAKESERNUM{n}"),
                }))
                .collect(),
            dmi_data: Some(DmiData {
                board_name: "DGXH100".into(),
                board_version: "555.07L01.0001".into(),
                bios_version: "1.6.7".into(),
                bios_date: "02/20/2025".into(),
                product_serial: self.dgx_system_serial_number.to_string(),
                board_serial: format!("{}.FAKESERNUM1", self.dgx_system_serial_number),
                chassis_serial: self.dgx_chassis_serial_number.to_string(),
                product_name: "DGXH100".into(),
                sys_vendor: "NVIDIA".into(),
            }),
            dpu_info: None,
            gpus: (0..8)
                .map(|n| {
                    let pci_bus_id = [
                        "00000000:1B:00.0",
                        "00000000:43:00.0",
                        "00000000:52:00.0",
                        "00000000:61:00.0",
                        "00000000:9D:00.0",
                        "00000000:C3:00.0",
                        "00000000:D1:00.0",
                        "00000000:DF:00.0",
                    ][n];
                    Gpu {
                        name: "NVIDIA H100 80GB HBM3".into(),
                        serial: self.gpu_serial[n].to_string(),
                        driver_version: "580.126.16".into(),
                        vbios_version: "96.00.A5.00.01".into(),
                        inforom_version: "G520.0200.00.05".into(),
                        total_memory: "81559 MiB".into(),
                        frequency: "1980 MHz".into(),
                        pci_bus_id: pci_bus_id.into(),
                        platform_info: None,
                    }
                })
                .collect(),
            memory_devices: (0..32)
                .map(|_| MemoryDevice {
                    size_mb: Some(65536),
                    mem_type: Some("DDR5".into()),
                })
                .collect(),
            tpm_ek_certificate: None,
            tpm_description: None,
            ..Default::default()
        }
    }

    fn discovery_info_network_interfaces(&self) -> Vec<NetworkInterface> {
        vec![
            self.mgmt_nic.discovery_info(
                "/devices/pci0000:00/0000:00:10.0/0000:0b:00.0/net/eno3",
                "0000:0b:00.0",
                0,
            ),
            self.storage_nic0.discovery_info(
                0,
                "/devices/pci0000:24\
                /0000:24:01.0/0000:25:00.0/0000:26:00.0\
                /0000:27:00.0/0000:28:00.0/0000:29:00.0\
                /net/enp41s0f0np0",
                "0000:29:00.0",
                0,
            ),
            self.storage_nic0.discovery_info(
                1,
                "/devices/pci0000:24/0000:24:01.0\
                /0000:25:00.0/0000:26:00.0/0000:27:00.0\
                /0000:28:00.0/0000:29:00.1\
                /net/enp41s0f1np1",
                "0000:29:00.1",
                0,
            ),
            self.dpu.host_nic_discovery_info(
                "/devices/pci0000:80/0000:80:05.0/0000:82:00.0/net/ens6np0",
                "0000:82:00.0",
                0,
            ),
        ]
    }

    fn discovery_info_ib_interfaces(&self) -> Vec<InfinibandInterface> {
        self.ib_nics
            .iter()
            .flat_map(|nic| nic.ib_nics())
            .enumerate()
            .map(|(n, _nic)| {
                let (bus, numa_node) = [
                    (0x15, 0),
                    (0x3d, 0),
                    (0x4c, 0),
                    (0x5b, 0),
                    (0x97, 1),
                    (0xbd, 1),
                    (0xcb, 1),
                    (0xd9, 1),
                ][n];
                let device_name = format!("ibp{bus}s0");
                let path = format!(
                    "/devices/pci0000:{:02x}/0000:{:02x}:01.0/0000:{:02x}:00.0/\
                     0000:{:02x}:00.0/0000:{:02x}:00.0/infiniband/{device_name}",
                    bus,
                    bus,
                    bus + 1,
                    bus + 2,
                    bus + 3
                );
                InfinibandInterface {
                    pci_properties: Some(PciDeviceProperties {
                        vendor: "Mellanox Technologies".into(),
                        device: "MT2910 Family [ConnectX-7]".into(),
                        path,
                        numa_node,
                        description: Some("MT2910 Family [ConnectX-7]".into()),
                        slot: format!("0000:{:02x}:00.0", bus + 3).into(),
                    }),
                    guid: format!("94dae0000000000{n}"),
                }
            })
            .collect()
    }
}

fn base_bios(system_id: &str) -> serde_json::Value {
    redfish::bios::builder(&redfish::bios::resource(system_id))
        .attributes(json!({
            "AcpiSpcrConsoleRedirectionEnable": true,
            "ConsoleRedirectionEnable0": true,
            "AcpiSpcrPort": "COM0",
            "AcpiSpcrFlowControl": "None",
            "AcpiSpcrBaudRate": "115200",
            "BaudRate0": "115200",
            "SriovSupport": "Enabled",
            "VTdSupport": "Enable",
            "Ipv4Http": "Enabled",
            "Ipv4Pxe": "Disabled",
            "Ipv6Http": "Enabled",
            "Ipv6Pxe": "Disabled",
            "NvidiaInfiniteboot": "Enable",
        }))
        .build()
        // For some reasons libredfish requires @odata.context. This
        // patch makes it happy.
        .patch(json!({
            "@odata.context": "MakeLibRedfishHappy"
        }))
}

fn hgx_gpu_sxm_chassis(index: usize, serial: &str) -> redfish::chassis::SingleChassisConfig {
    let id = format!("HGX_GPU_SXM_{index}");
    redfish::chassis::SingleChassisConfig {
        chassis_type: "Other".into(),
        manufacturer: Some("NVIDIA".into()),
        part_number: Some("2330-885-A1".into()),
        model: Some("H100 80GB HBM3".into()),
        serial_number: Some(serial.to_string().into()),
        network_adapters: None,
        pcie_devices: Some(vec![
            redfish::pcie_device::builder(&redfish::pcie_device::chassis_resource(
                &id,
                &format!("GPU_SXM_{index}"),
            ))
            .manufacturer("NVIDIA")
            .model("H100 80GB HBM3")
            .part_number("2330-885-A1")
            .serial_number(serial)
            .build(),
        ]),
        sensors: Some(redfish::sensor::generate_chassis_sensors(
            &id,
            redfish::sensor::Layout {
                temperature: 3,
                power: 2,
                leak: 1, // Voltage
                ..Default::default()
            },
        )),
        id: id.into(),
        assembly: None,
        oem: None,
    }
}
