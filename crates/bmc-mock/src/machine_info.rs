/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
use std::sync::atomic::{AtomicU32, Ordering};

use mac_address::MacAddress;
use serde::{Deserialize, Serialize};

use crate::redfish;

static NEXT_MAC_ADDRESS: AtomicU32 = AtomicU32::new(1);

/// Represents static information we know ahead of time about a host or DPU (independent of any
/// state we get from carbide like IP addresses or machine ID's.) Intended to be immutable and
/// easily cloneable.
#[derive(Debug, Clone)]
pub enum MachineInfo {
    Host(HostMachineInfo),
    Dpu(DpuMachineInfo),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostMachineInfo {
    pub bmc_mac_address: MacAddress,
    pub serial: String,
    pub dpus: Vec<DpuMachineInfo>,
    pub non_dpu_mac_address: Option<MacAddress>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpuMachineInfo {
    pub bmc_mac_address: MacAddress,
    pub host_mac_address: MacAddress,
    pub oob_mac_address: MacAddress,
    pub serial: String,
    pub nic_mode: bool,
    pub firmware_versions: DpuFirmwareVersions,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DpuFirmwareVersions {
    pub bmc: Option<String>,
    pub uefi: Option<String>,
    pub cec: Option<String>,
    pub nic: Option<String>,
}

impl Default for DpuMachineInfo {
    fn default() -> Self {
        Self::new(false, Default::default())
    }
}

impl DpuMachineInfo {
    pub fn new(nic_mode: bool, firmware_versions: DpuFirmwareVersions) -> Self {
        let bmc_mac_address = next_mac();
        let host_mac_address = next_mac();
        let oob_mac_address = next_mac();
        Self {
            bmc_mac_address,
            host_mac_address,
            oob_mac_address,
            nic_mode,
            firmware_versions,
            serial: format!("MT{}", oob_mac_address.to_string().replace(':', "")),
        }
    }
}

impl HostMachineInfo {
    pub fn new(dpus: Vec<DpuMachineInfo>) -> Self {
        let bmc_mac_address = next_mac();
        Self {
            bmc_mac_address,
            serial: bmc_mac_address.to_string().replace(':', ""),
            non_dpu_mac_address: if dpus.is_empty() {
                Some(next_mac())
            } else {
                None
            },
            dpus,
        }
    }

    pub fn primary_dpu(&self) -> Option<&DpuMachineInfo> {
        self.dpus.first()
    }

    pub fn system_mac_address(&self) -> Option<MacAddress> {
        self.primary_dpu()
            .map(|d| d.host_mac_address)
            .or(self.non_dpu_mac_address)
    }
}

impl MachineInfo {
    pub fn manager_config(&self) -> redfish::manager::Config {
        match self {
            MachineInfo::Dpu(dpu) => redfish::manager::Config {
                id: "Bluefield_BMC",
                eth_interfaces: vec![
                    redfish::ethernet_interface::builder(
                        &redfish::ethernet_interface::manager_resource("Bluefield_BMC", "eth0"),
                    )
                    .mac_address(dpu.bmc_mac_address)
                    .interface_enabled(true)
                    .build(),
                ],
                firmware_version: "BF-23.10-4",
            },
            MachineInfo::Host(host) => redfish::manager::Config {
                id: "iDRAC.Embedded.1",
                eth_interfaces: vec![
                    redfish::ethernet_interface::builder(
                        &redfish::ethernet_interface::manager_resource("iDRAC.Embedded.1", "NIC.1"),
                    )
                    .mac_address(host.bmc_mac_address)
                    .interface_enabled(true)
                    .build(),
                ],
                firmware_version: "6.00.30.00",
            },
        }
    }

    pub fn system_config(
        &self,
        power_control: Arc<dyn crate::PowerControl>,
    ) -> redfish::computer_system::SystemConfig {
        match self {
            MachineInfo::Host(host) => {
                let power_control = Some(power_control.clone());
                let serial_number = self.product_serial().clone();
                let eth_interfaces = self
                    .dhcp_mac_addresses()
                    .into_iter()
                    .enumerate()
                    .map(|(index, mac)| {
                        let eth_id = Cow::Owned(format!("NIC.Slot.{}", index + 1));
                        let resource = redfish::ethernet_interface::system_resource(
                            "System.Embedded.1",
                            &eth_id,
                        );
                        redfish::ethernet_interface::builder(&resource)
                            .mac_address(mac)
                            .interface_enabled(true)
                            .build()
                    })
                    .collect();
                redfish::computer_system::SystemConfig {
                    bmc_vendor: redfish::oem::BmcVendor::Dell,
                    systems: vec![redfish::computer_system::SingleSystemConfig {
                        id: Cow::Borrowed("System.Embedded.1"),
                        eth_interfaces,
                        serial_number,
                        pcie_dpu_count: host.dpus.len(),
                        boot_order_mode: redfish::computer_system::BootOrderMode::DellOem,
                        power_control,
                    }],
                }
            }
            MachineInfo::Dpu(dpu) => redfish::computer_system::SystemConfig {
                bmc_vendor: redfish::oem::BmcVendor::Nvidia,
                systems: vec![redfish::computer_system::SingleSystemConfig {
                    id: Cow::Borrowed("Bluefield"),
                    eth_interfaces: vec![
                        redfish::ethernet_interface::builder(
                            &redfish::ethernet_interface::system_resource("Bluefield", "eth0"),
                        )
                        .mac_address(dpu.host_mac_address)
                        .interface_enabled(true)
                        .build(),
                        redfish::ethernet_interface::builder(
                            &redfish::ethernet_interface::system_resource("Bluefield", "oob0"),
                        )
                        .mac_address(dpu.oob_mac_address)
                        .interface_enabled(true)
                        .build(),
                    ],
                    serial_number: self.product_serial().clone(),
                    pcie_dpu_count: 0,
                    boot_order_mode: redfish::computer_system::BootOrderMode::Generic,
                    power_control: Some(power_control),
                }],
            },
        }
    }

    pub fn chassis_serial(&self) -> Option<String> {
        match self {
            Self::Host(h) => Some(h.serial.clone()),
            Self::Dpu(_) => None,
        }
    }

    pub fn product_serial(&self) -> &String {
        match self {
            Self::Host(h) => &h.serial,
            Self::Dpu(d) => &d.serial,
        }
    }

    pub fn bmc_mac_address(&self) -> MacAddress {
        match self {
            Self::Host(h) => h.bmc_mac_address,
            Self::Dpu(d) => d.bmc_mac_address,
        }
    }

    /// Returns the mac addresses this system would use to request DHCP on boot
    pub fn dhcp_mac_addresses(&self) -> Vec<MacAddress> {
        match self {
            Self::Host(h) => {
                if h.dpus.is_empty() {
                    h.non_dpu_mac_address.map(|m| vec![m]).unwrap_or_default()
                } else {
                    h.dpus.iter().map(|d| d.host_mac_address).collect()
                }
            }
            Self::Dpu(d) => vec![d.oob_mac_address],
        }
    }

    // If this is a DPU, return its host mac address
    pub fn host_mac_address(&self) -> Option<MacAddress> {
        if let Self::Dpu(d) = self {
            Some(d.host_mac_address)
        } else {
            None
        }
    }
}

fn next_mac() -> MacAddress {
    let next_mac_num = NEXT_MAC_ADDRESS.fetch_add(1, Ordering::Acquire);

    let bytes: Vec<u8> = [0x02u8, 0x01]
        .into_iter()
        .chain(next_mac_num.to_be_bytes())
        .collect();

    let mac_bytes = <[u8; 6]>::try_from(bytes).unwrap();

    MacAddress::from(mac_bytes)
}
