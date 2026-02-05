/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::borrow::Cow;
use std::sync::Arc;

use mac_address::MacAddress;
use serde_json::json;

use crate::{PowerControl, redfish};

pub struct Bluefield3<'a> {
    pub product_serial_number: Cow<'a, str>,
    pub bmc_mac_address: MacAddress,
    pub oob_mac_address: Option<MacAddress>,
    pub nic_mode: bool,
}

impl Bluefield3<'_> {
    pub fn chassis_config(&self) -> redfish::chassis::ChassisConfig {
        redfish::chassis::ChassisConfig {
            chassis: vec![
                redfish::chassis::SingleChassisConfig {
                    id: "Bluefield_BMC".into(),
                    manufacturer: Some("Nvidia".into()),
                    model: Some("BlueField-3 DPU".into()),
                    network_adapters: Some(vec![]),
                    part_number: Some(Cow::Borrowed(self.part_number())),
                    pcie_devices: Some(vec![]),
                    serial_number: Some(self.product_serial_number.to_string().into()),
                },
                redfish::chassis::SingleChassisConfig {
                    id: "Bluefield_ERoT".into(),
                    manufacturer: Some(Cow::Borrowed("NVIDIA")),
                    model: None,
                    network_adapters: None,
                    part_number: None,
                    pcie_devices: None,
                    serial_number: Some("".into()),
                },
                redfish::chassis::SingleChassisConfig {
                    id: "CPU_0".into(),
                    manufacturer: Some("https://www.mellanox.com".into()),
                    model: Some("Mellanox BlueField-3 [A1] A78(D42) 16 Cores r0p1".into()),
                    network_adapters: Some(vec![]),
                    part_number: Some(format!("OPN: {}", self.opn()).into()),
                    serial_number: Some("Unspecified Serial Number".into()),
                    pcie_devices: Some(vec![]),
                },
                redfish::chassis::SingleChassisConfig {
                    id: "Card1".into(),
                    manufacturer: Some("Nvidia".into()),
                    model: Some("BlueField-3 DPU".into()),
                    network_adapters: Some(vec![]),
                    part_number: Some(self.part_number().into()),
                    pcie_devices: Some(vec![]),
                    serial_number: Some(self.product_serial_number.to_string().into()),
                },
            ],
        }
    }

    pub fn system_config(
        &self,
        pc: Arc<dyn PowerControl>,
    ) -> redfish::computer_system::SystemConfig {
        let system_id = "Bluefield";
        let boot_opt_builder = |id: &str| {
            redfish::boot_option::builder(&redfish::boot_option::resource(system_id, id))
                .boot_option_reference(id)
        };
        let nic_mode = if self.nic_mode { "NicMode" } else { "DpuMode" };
        let eth_interfaces =
            self.oob_mac_address
                .iter()
                .map(|mac| {
                    redfish::ethernet_interface::builder(
                        &redfish::ethernet_interface::system_resource("Bluefield", "oob_net0"),
                    )
                    .mac_address(*mac)
                    .description("1G DPU OOB network interface")
                    .build()
                })
                .collect();
        let boot_options = [
            boot_opt_builder("Boot0040")
                .display_name("ubuntu0")
                .uefi_device_path("HD(1,GPT,2FAFB38D-05F6-DF41-AE01-F9991E2CC0F0,0x800,0x19000)/\\EFI\\ubuntu\\shimaa64.efi")
                .build()
        ].into_iter().chain(self.oob_mac_address.iter().flat_map(|mac| {
            let mocked_mac_no_colons = mac
                .to_string()
                .replace(':', "")
                .to_ascii_uppercase();
            vec![
                boot_opt_builder("Boot0000")
                    .display_name("NET-OOB-IPV4-HTTP")
                    .uefi_device_path(&format!("MAC({mocked_mac_no_colons},0x1)/IPv4(0.0.0.0,0x0,DHCP,0.0.0.0,0.0.0.0,0.0.0.0)/Uri()"))
                    .build(),
            ]
        })).collect();

        redfish::computer_system::SystemConfig {
            systems: vec![redfish::computer_system::SingleSystemConfig {
                id: Cow::Borrowed("Bluefield"),
                manufacturer: Some(Cow::Borrowed("Nvidia")),
                model: Some(Cow::Borrowed("BlueField-3 DPU")),
                eth_interfaces,
                chassis: vec!["Bluefield_BMC".into()],
                serial_number: self.product_serial_number.to_string().into(),
                boot_order_mode: redfish::computer_system::BootOrderMode::Generic,
                power_control: Some(pc),
                boot_options,
                bios_mode: redfish::computer_system::BiosMode::Generic,
                base_bios: redfish::bios::builder(&redfish::bios::resource(system_id))
                    .attributes(json!({
                        "NicMode": nic_mode,
                        "HostPrivilegeLevel": "Unavailable",
                        "InternalCPUModel": "Unavailable",
                    }))
                    .build(),
            }],
        }
    }

    pub fn manager_config(&self) -> redfish::manager::Config {
        redfish::manager::Config {
            id: "Bluefield_BMC",
            eth_interfaces: vec![
                redfish::ethernet_interface::builder(
                    &redfish::ethernet_interface::manager_resource("Bluefield_BMC", "eth0"),
                )
                .mac_address(self.bmc_mac_address)
                .interface_enabled(true)
                .build(),
            ],
            firmware_version: "BF-23.10-4",
        }
    }

    fn part_number(&self) -> &'static str {
        // Set the BF3 Part Number based on whether the DPU is supposed to be in NIC mode or not
        // Use a BF3 SuperNIC OPN if the DPU is supposed to be in NIC mode. Otherwise, use
        // a BF3 DPU OPN. Site explorer assumes that BF3 SuperNICs must be in NIC mode and that
        // BF3 DPUs must be in DPU mode. It will not ingest a host if any of the BF3 DPUs in the host
        // are in NIC mode or if any of the BF3 SuperNICs in the host are in DPU mode.
        // OPNs taken from: https://docs.nvidia.com/networking/display/bf3dpu
        match self.nic_mode {
            true => "900-9D3B4-00CC-EA0",
            false => "900-9D3B6-00CV-AA0",
        }
    }

    fn opn(&self) -> &'static str {
        // This is wild guess that OPN (Ordering Part Number) is
        // changing together with NIC-mode.
        match self.nic_mode {
            true => "9009D3B400CCEA",
            false => "9009D3B600CVAA",
        }
    }
}
