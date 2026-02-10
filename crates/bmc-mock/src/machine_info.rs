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
use std::sync::atomic::{AtomicU32, Ordering};

use mac_address::MacAddress;
use serde::{Deserialize, Serialize};

use crate::redfish::update_service::UpdateServiceConfig;
use crate::{hw, redfish};
static NEXT_MAC_ADDRESS: AtomicU32 = AtomicU32::new(1);
use crate::HostHardwareType;

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
    pub hw_type: HostHardwareType,
    pub bmc_mac_address: MacAddress,
    pub serial: String,
    pub dpus: Vec<DpuMachineInfo>,
    pub non_dpu_mac_address: Option<MacAddress>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpuMachineInfo {
    pub hw_type: HostHardwareType,
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
        Self::new(
            HostHardwareType::DellPowerEdgeR750,
            false,
            Default::default(),
        )
    }
}

impl DpuMachineInfo {
    pub fn new(
        hw_type: HostHardwareType,
        nic_mode: bool,
        firmware_versions: DpuFirmwareVersions,
    ) -> Self {
        let bmc_mac_address = next_mac();
        let host_mac_address = next_mac();
        let oob_mac_address = next_mac();
        Self {
            hw_type,
            bmc_mac_address,
            host_mac_address,
            oob_mac_address,
            nic_mode,
            firmware_versions,
            serial: format!("MT{}", oob_mac_address.to_string().replace(':', "")),
        }
    }

    fn bluefield3(&self) -> hw::bluefield3::Bluefield3<'_> {
        let mode = match self.hw_type {
            HostHardwareType::DellPowerEdgeR750 => hw::bluefield3::Mode::SuperNIC {
                nic_mode: self.nic_mode,
            },
            HostHardwareType::WiwynnGB200Nvl => hw::bluefield3::Mode::B3240ColdAisle,
        };
        hw::bluefield3::Bluefield3 {
            host_mac_address: self.host_mac_address,
            bmc_mac_address: self.bmc_mac_address,
            oob_mac_address: Some(self.oob_mac_address),
            mode,
            product_serial_number: Cow::Borrowed(&self.serial),
            firmware_versions: hw::bluefield3::FirmwareVersions {
                bmc: self.firmware_versions.bmc.clone().unwrap_or_default(),
                uefi: self.firmware_versions.uefi.clone().unwrap_or_default(),
                erot: self.firmware_versions.cec.clone().unwrap_or_default(),
                dpu_nic: self.firmware_versions.nic.clone().unwrap_or_default(),
            },
        }
    }
}

impl HostMachineInfo {
    pub fn new(hw_type: HostHardwareType, dpus: Vec<DpuMachineInfo>) -> Self {
        let bmc_mac_address = next_mac();
        Self {
            hw_type,
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

    pub fn oem_state(&self) -> redfish::oem::State {
        match self.hw_type {
            HostHardwareType::DellPowerEdgeR750 => {
                redfish::oem::State::DellIdrac(redfish::oem::dell::idrac::IdracState::default())
            }
            HostHardwareType::WiwynnGB200Nvl => redfish::oem::State::Other,
        }
    }

    pub fn bmc_vendor(&self) -> redfish::oem::BmcVendor {
        match self.hw_type {
            HostHardwareType::DellPowerEdgeR750 => redfish::oem::BmcVendor::Dell,
            HostHardwareType::WiwynnGB200Nvl => redfish::oem::BmcVendor::Wiwynn,
        }
    }

    pub fn manager_config(&self) -> redfish::manager::Config {
        match self.hw_type {
            HostHardwareType::DellPowerEdgeR750 => self.dell_poweredge_r750().manager_config(),
            HostHardwareType::WiwynnGB200Nvl => self.wiwynn_gb200_nvl().manager_config(),
        }
    }

    pub fn system_config(
        &self,
        power_control: Arc<dyn crate::PowerControl>,
    ) -> redfish::computer_system::Config {
        match self.hw_type {
            HostHardwareType::DellPowerEdgeR750 => {
                self.dell_poweredge_r750().system_config(power_control)
            }
            HostHardwareType::WiwynnGB200Nvl => {
                self.wiwynn_gb200_nvl().system_config(power_control)
            }
        }
    }

    pub fn chassis_config(&self) -> redfish::chassis::ChassisConfig {
        match self.hw_type {
            HostHardwareType::DellPowerEdgeR750 => self.dell_poweredge_r750().chassis_config(),
            HostHardwareType::WiwynnGB200Nvl => self.wiwynn_gb200_nvl().chassis_config(),
        }
    }

    pub fn update_service_config(&self) -> UpdateServiceConfig {
        match self.hw_type {
            HostHardwareType::DellPowerEdgeR750 => {
                self.dell_poweredge_r750().update_service_config()
            }
            HostHardwareType::WiwynnGB200Nvl => self.wiwynn_gb200_nvl().update_service_config(),
        }
    }

    fn dell_poweredge_r750(&self) -> hw::dell_poweredge_r750::DellPowerEdgeR750<'_> {
        let nics = if self.dpus.is_empty() {
            self.non_dpu_mac_address
                .iter()
                .enumerate()
                .map(|(index, mac_address)| (index + 1, hw::nic::Nic::rooftop(*mac_address)))
                .collect()
        } else {
            self.dpus
                .iter()
                .enumerate()
                .map(|(index, dpu)| (index + 1, dpu.bluefield3().host_nic()))
                .collect()
        };
        hw::dell_poweredge_r750::DellPowerEdgeR750 {
            bmc_mac_address: self.bmc_mac_address,
            product_serial_number: Cow::Borrowed(&self.serial),
            nics,
            embedded_nic: hw::dell_poweredge_r750::EmbeddedNic {
                port_1: next_mac(),
                port_2: next_mac(),
            },
        }
    }

    fn wiwynn_gb200_nvl(&self) -> hw::wiwynn_gb200_nvl::WiwynnGB200Nvl<'_> {
        let mut dpus = self.dpus.iter();
        hw::wiwynn_gb200_nvl::WiwynnGB200Nvl {
            product_serial_number: Cow::Borrowed(&self.serial),
            dpu1: dpus
                .next()
                .expect("Two DPUs must present for GB200 NVL")
                .bluefield3(),
            dpu2: dpus
                .next()
                .expect("Two DPUs must present for GB200 NVL")
                .bluefield3(),
        }
    }
}

impl MachineInfo {
    pub fn oem_state(&self) -> redfish::oem::State {
        match self {
            MachineInfo::Host(host) => host.oem_state(),
            MachineInfo::Dpu(dpu) => redfish::oem::State::NvidiaBluefield(
                redfish::oem::nvidia::bluefield::BluefieldState::new(dpu.nic_mode),
            ),
        }
    }

    pub fn manager_config(&self) -> redfish::manager::Config {
        match self {
            MachineInfo::Host(host) => host.manager_config(),
            MachineInfo::Dpu(dpu) => dpu.bluefield3().manager_config(),
        }
    }

    pub fn bmc_vendor(&self) -> redfish::oem::BmcVendor {
        match self {
            MachineInfo::Host(h) => h.bmc_vendor(),
            MachineInfo::Dpu(_) => redfish::oem::BmcVendor::Nvidia,
        }
    }

    pub fn system_config(
        &self,
        power_control: Arc<dyn crate::PowerControl>,
    ) -> redfish::computer_system::Config {
        match self {
            MachineInfo::Host(host) => host.system_config(power_control),
            MachineInfo::Dpu(dpu) => dpu.bluefield3().system_config(power_control),
        }
    }

    pub fn chassis_config(&self) -> redfish::chassis::ChassisConfig {
        match self {
            Self::Host(h) => h.chassis_config(),
            Self::Dpu(dpu) => dpu.bluefield3().chassis_config(),
        }
    }

    pub fn update_service_config(&self) -> UpdateServiceConfig {
        match self {
            Self::Host(h) => h.update_service_config(),
            Self::Dpu(dpu) => dpu.bluefield3().update_service_config(),
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
