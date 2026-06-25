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
use serde::{Deserialize, Serialize};

use crate::mac_address_pool::{MacAddressPool, PoolConfig as MacAddressPoolConfig};
use crate::redfish::update_service::UpdateServiceConfig;
use crate::{
    DUMMY_FACTORY_DPU_PASSWORD, DUMMY_FACTORY_PASSWORD, DUMMY_FACTORY_USERNAME, HostHardwareType,
    hw, redfish,
};

/// Represents static information we know ahead of time about a host or DPU (independent of any
/// state we get from carbide like IP addresses or machine ID's.) Intended to be immutable and
/// easily cloneable.
#[derive(Debug, Clone)]
pub enum MachineInfo {
    Host(HostMachineInfo),
    Dpu(DpuMachineInfo),
}

#[derive(Debug, Clone)]
pub struct HostMachineInfo {
    pub hw_type: HostHardwareType,
    pub bmc_mac_address: MacAddress,
    pub serial: String,
    pub dpus: Vec<DpuMachineInfo>,
    pub non_dpu_mac_address: Option<MacAddress>,
    pub nvos_mac_addresses: Vec<MacAddress>,
    pub switch_serial_number: Option<String>,
    pub hw_mac_addr_pool: MacAddressPoolConfig,
}

#[derive(Debug, Clone)]
pub struct DpuMachineInfo {
    pub hw_type: HostHardwareType,
    pub bmc_mac_address: MacAddress,
    pub host_mac_address: MacAddress,
    pub oob_mac_address: MacAddress,
    pub serial: String,
    pub settings: DpuSettings,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DpuFirmwareVersions {
    pub bmc: Option<String>,
    pub uefi: Option<String>,
    pub cec: Option<String>,
    pub nic: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpuSettings {
    pub nic_mode: bool,
    pub firmware_versions: DpuFirmwareVersions,
    #[serde(default = "default_true")]
    pub exposes_oob_eth: bool,
}

fn default_true() -> bool {
    true
}

impl Default for DpuSettings {
    fn default() -> Self {
        Self {
            nic_mode: false,
            firmware_versions: Default::default(),
            exposes_oob_eth: true,
        }
    }
}

impl DpuMachineInfo {
    pub fn new(
        hw_type: HostHardwareType,
        pool: &mut MacAddressPool,
        settings: DpuSettings,
    ) -> Self {
        let mut next_mac = || pool.allocate().expect("MAC address must be allocated");
        let bmc_mac_address = next_mac();
        let host_mac_address = next_mac();
        let oob_mac_address = next_mac();
        Self {
            hw_type,
            bmc_mac_address,
            host_mac_address,
            oob_mac_address,
            settings,
            serial: format!("MT{}", oob_mac_address.to_string().replace(':', "")),
        }
    }

    fn bluefield3(&self) -> hw::bluefield3::Bluefield3<'_> {
        let mode = match self.hw_type {
            HostHardwareType::DellPowerEdgeR750
            | HostHardwareType::NvidiaDgxH100
            | HostHardwareType::GenericAmi
            | HostHardwareType::GenericSupermicro => hw::bluefield3::Mode::SuperNIC {
                nic_mode: self.settings.nic_mode,
            },
            // GB-class cold-aisle DPU mode. Confirmed for GB200; for DGX/SMC GB300 the BF3
            // chassis is in the scrape but the mode is not separately confirmed (synthetic).
            HostHardwareType::WiwynnGB200Nvl
            | HostHardwareType::LenovoGB300Nvl
            | HostHardwareType::NvidiaDgxGb300
            | HostHardwareType::SupermicroGb300Nvl => hw::bluefield3::Mode::B3240ColdAisle,
            HostHardwareType::LiteOnPowerShelf | HostHardwareType::NvidiaSwitchNd5200Ld => {
                panic!("Bluefield3 DPU is defined for {}", self.hw_type)
            }
        };
        let settings = &self.settings;
        hw::bluefield3::Bluefield3 {
            host_mac_address: self.host_mac_address,
            bmc_mac_address: self.bmc_mac_address,
            oob_mac_address: settings.exposes_oob_eth.then_some(self.oob_mac_address),
            mode,
            product_serial_number: Cow::Borrowed(&self.serial),
            firmware_versions: hw::bluefield3::FirmwareVersions {
                bmc: settings.firmware_versions.bmc.clone().unwrap_or_default(),
                uefi: settings.firmware_versions.uefi.clone().unwrap_or_default(),
                erot: settings.firmware_versions.cec.clone().unwrap_or_default(),
                dpu_nic: settings.firmware_versions.nic.clone().unwrap_or_default(),
            },
        }
    }
}

impl HostMachineInfo {
    pub fn new(
        hw_type: HostHardwareType,
        dpus: Vec<DpuMachineInfo>,
        pool: &mut MacAddressPool,
        hw_mac_addr_pool: MacAddressPoolConfig,
    ) -> Self {
        let mut next_mac = || pool.allocate().expect("MAC address must be allocated");
        let bmc_mac_address = next_mac();
        let nvos_mac_addresses = if matches!(hw_type, HostHardwareType::NvidiaSwitchNd5200Ld) {
            vec![next_mac()]
        } else {
            vec![]
        };
        let switch_serial_number = nvos_mac_addresses
            .first()
            .map(|mac| format!("MT{}", mac.to_string().replace(':', "")));
        Self {
            hw_type,
            bmc_mac_address,
            serial: bmc_mac_address.to_string().replace(':', ""),
            non_dpu_mac_address: if dpus.is_empty()
                && !matches!(
                    hw_type,
                    HostHardwareType::LiteOnPowerShelf | HostHardwareType::NvidiaSwitchNd5200Ld
                ) {
                Some(next_mac())
            } else {
                None
            },
            nvos_mac_addresses,
            switch_serial_number,
            dpus,
            hw_mac_addr_pool,
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
            HostHardwareType::WiwynnGB200Nvl
            | HostHardwareType::LenovoGB300Nvl
            | HostHardwareType::NvidiaDgxGb300
            | HostHardwareType::SupermicroGb300Nvl
            | HostHardwareType::LiteOnPowerShelf
            | HostHardwareType::NvidiaDgxH100
            | HostHardwareType::NvidiaSwitchNd5200Ld
            | HostHardwareType::GenericAmi
            | HostHardwareType::GenericSupermicro => redfish::oem::State::Other,
        }
    }

    pub fn bmc_vendor(&self) -> redfish::oem::BmcVendor {
        match self.hw_type {
            HostHardwareType::DellPowerEdgeR750 => redfish::oem::BmcVendor::Dell,
            HostHardwareType::WiwynnGB200Nvl => redfish::oem::BmcVendor::Wiwynn,
            HostHardwareType::LenovoGB300Nvl => redfish::oem::BmcVendor::Ami,
            HostHardwareType::NvidiaDgxGb300 => {
                redfish::oem::BmcVendor::Nvidia(redfish::oem::NvidiaNamestyle::Uppercase)
            }
            HostHardwareType::SupermicroGb300Nvl => redfish::oem::BmcVendor::Supermicro,
            HostHardwareType::LiteOnPowerShelf => redfish::oem::BmcVendor::LiteOn,
            HostHardwareType::NvidiaSwitchNd5200Ld => {
                redfish::oem::BmcVendor::Nvidia(redfish::oem::NvidiaNamestyle::Uppercase)
            }
            HostHardwareType::NvidiaDgxH100 => redfish::oem::BmcVendor::Ami,
            HostHardwareType::GenericAmi => redfish::oem::BmcVendor::Ami,
            HostHardwareType::GenericSupermicro => redfish::oem::BmcVendor::Supermicro,
        }
    }

    pub fn bmc_product(&self) -> Option<&'static str> {
        match self.hw_type {
            HostHardwareType::DellPowerEdgeR750 => None,
            HostHardwareType::WiwynnGB200Nvl => Some("GB200 NVL"),
            HostHardwareType::LenovoGB300Nvl => Some("AMI Redfish Server"),
            HostHardwareType::NvidiaDgxGb300 => Some("GB BMC"),
            HostHardwareType::SupermicroGb300Nvl => Some("GB NVL"),
            HostHardwareType::LiteOnPowerShelf => None,
            HostHardwareType::NvidiaSwitchNd5200Ld => Some("P3809"),
            HostHardwareType::NvidiaDgxH100 => Some("AMI Redfish Server"),
            HostHardwareType::GenericAmi => Some("AMI Redfish Server"),
            HostHardwareType::GenericSupermicro => Some("Super Server"),
        }
    }

    pub fn bmc_redfish_version(&self) -> &'static str {
        match self.hw_type {
            HostHardwareType::DellPowerEdgeR750 => "1.18.0",
            HostHardwareType::WiwynnGB200Nvl => "1.17.0",
            HostHardwareType::LenovoGB300Nvl => "1.21.1",
            HostHardwareType::NvidiaDgxGb300 => "1.17.0",
            HostHardwareType::SupermicroGb300Nvl => "1.17.0",
            HostHardwareType::LiteOnPowerShelf => "1.9.0",
            HostHardwareType::NvidiaSwitchNd5200Ld => "1.17.0",
            HostHardwareType::NvidiaDgxH100 => "1.11.0",
            HostHardwareType::GenericAmi => "1.17.0",
            HostHardwareType::GenericSupermicro => "1.17.0",
        }
    }

    pub fn manager_config(&self) -> redfish::manager::Config {
        match self.hw_type {
            HostHardwareType::DellPowerEdgeR750 => self.dell_poweredge_r750().manager_config(),
            HostHardwareType::WiwynnGB200Nvl => self.wiwynn_gb200_nvl().manager_config(),
            HostHardwareType::LenovoGB300Nvl => self.lenovo_gb300_nvl().manager_config(),
            HostHardwareType::NvidiaDgxGb300 => self.dgx_gb300_nvl().manager_config(),
            HostHardwareType::SupermicroGb300Nvl => self.supermicro_gb300_nvl().manager_config(),
            HostHardwareType::LiteOnPowerShelf => self.liteon_power_shelf().manager_config(),
            HostHardwareType::NvidiaSwitchNd5200Ld => {
                self.nvidia_switch_nd5200_ld().manager_config()
            }
            HostHardwareType::NvidiaDgxH100 => self.nvidia_dgx_h100().manager_config(),
            HostHardwareType::GenericAmi | HostHardwareType::GenericSupermicro => {
                self.generic_server().manager_config()
            }
        }
    }

    pub fn system_config(
        &self,
        callbacks: Arc<dyn crate::Callbacks>,
    ) -> redfish::computer_system::Config {
        match self.hw_type {
            HostHardwareType::DellPowerEdgeR750 => {
                self.dell_poweredge_r750().system_config(callbacks)
            }
            HostHardwareType::WiwynnGB200Nvl => self.wiwynn_gb200_nvl().system_config(callbacks),
            HostHardwareType::LenovoGB300Nvl => self.lenovo_gb300_nvl().system_config(callbacks),
            HostHardwareType::NvidiaDgxGb300 => self.dgx_gb300_nvl().system_config(callbacks),
            HostHardwareType::SupermicroGb300Nvl => {
                self.supermicro_gb300_nvl().system_config(callbacks)
            }
            HostHardwareType::LiteOnPowerShelf => self.liteon_power_shelf().system_config(),
            HostHardwareType::NvidiaSwitchNd5200Ld => {
                self.nvidia_switch_nd5200_ld().system_config()
            }
            HostHardwareType::NvidiaDgxH100 => self.nvidia_dgx_h100().system_config(callbacks),
            HostHardwareType::GenericAmi | HostHardwareType::GenericSupermicro => {
                self.generic_server().system_config(callbacks)
            }
        }
    }

    pub fn chassis_config(&self) -> redfish::chassis::ChassisConfig {
        match self.hw_type {
            HostHardwareType::DellPowerEdgeR750 => self.dell_poweredge_r750().chassis_config(),
            HostHardwareType::WiwynnGB200Nvl => self.wiwynn_gb200_nvl().chassis_config(),
            HostHardwareType::LenovoGB300Nvl => self.lenovo_gb300_nvl().chassis_config(),
            HostHardwareType::NvidiaDgxGb300 => self.dgx_gb300_nvl().chassis_config(),
            HostHardwareType::SupermicroGb300Nvl => self.supermicro_gb300_nvl().chassis_config(),
            HostHardwareType::LiteOnPowerShelf => self.liteon_power_shelf().chassis_config(),
            HostHardwareType::NvidiaSwitchNd5200Ld => {
                self.nvidia_switch_nd5200_ld().chassis_config()
            }
            HostHardwareType::NvidiaDgxH100 => self.nvidia_dgx_h100().chassis_config(),
            HostHardwareType::GenericAmi | HostHardwareType::GenericSupermicro => {
                self.generic_server().chassis_config()
            }
        }
    }

    pub fn update_service_config(&self) -> UpdateServiceConfig {
        match self.hw_type {
            HostHardwareType::DellPowerEdgeR750 => {
                self.dell_poweredge_r750().update_service_config()
            }
            HostHardwareType::WiwynnGB200Nvl => self.wiwynn_gb200_nvl().update_service_config(),
            HostHardwareType::LenovoGB300Nvl => self.lenovo_gb300_nvl().update_service_config(),
            HostHardwareType::NvidiaDgxGb300 => self.dgx_gb300_nvl().update_service_config(),
            HostHardwareType::SupermicroGb300Nvl => {
                self.supermicro_gb300_nvl().update_service_config()
            }
            HostHardwareType::LiteOnPowerShelf => self.liteon_power_shelf().update_service_config(),
            HostHardwareType::NvidiaSwitchNd5200Ld => {
                self.nvidia_switch_nd5200_ld().update_service_config()
            }
            HostHardwareType::NvidiaDgxH100 => self.nvidia_dgx_h100().update_service_config(),
            HostHardwareType::GenericAmi | HostHardwareType::GenericSupermicro => {
                self.generic_server().update_service_config()
            }
        }
    }

    pub fn discovery_info(&self) -> rpc::machine_discovery::DiscoveryInfo {
        match self.hw_type {
            HostHardwareType::DellPowerEdgeR750 => self.dell_poweredge_r750().discovery_info(),
            HostHardwareType::WiwynnGB200Nvl => self.wiwynn_gb200_nvl().discovery_info(),
            HostHardwareType::LenovoGB300Nvl => self.lenovo_gb300_nvl().discovery_info(),
            HostHardwareType::NvidiaDgxGb300 => self.dgx_gb300_nvl().discovery_info(),
            HostHardwareType::SupermicroGb300Nvl => self.supermicro_gb300_nvl().discovery_info(),
            HostHardwareType::NvidiaDgxH100 => self.nvidia_dgx_h100().discovery_info(),
            HostHardwareType::GenericAmi | HostHardwareType::GenericSupermicro => {
                self.generic_server().discovery_info()
            }
            HostHardwareType::LiteOnPowerShelf | HostHardwareType::NvidiaSwitchNd5200Ld => {
                panic!("discovery_info requested for {}", self.hw_type)
            }
        }
    }

    pub fn factory_default_account(&self) -> redfish::account_service::Account {
        // TODO: need to be updated for each individual system.
        let id = match self.hw_type {
            HostHardwareType::NvidiaDgxH100 | HostHardwareType::GenericAmi => "2",
            _ => DUMMY_FACTORY_USERNAME,
        };
        redfish::account_service::Account::administrator(
            id,
            DUMMY_FACTORY_USERNAME,
            DUMMY_FACTORY_PASSWORD,
        )
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
        let mut pool = MacAddressPool::new_pool(self.hw_mac_addr_pool);
        let mut next_mac = || pool.allocate().expect("MAC address must be allocated");
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
            system_serial_number: Cow::Borrowed(&self.serial),
            chassis_serial_number: Cow::Borrowed(&self.serial),
            compute_board: [
                hw::nvidia_gb200::BiancaBoard {
                    index: hw::nvidia_gb200::BoardIndex::Board0,
                    cpu_serial_number: "0x000000017FFFFFFFFF00000000000001".into(),
                    gpu_serial_number: "165300000001".into(),
                },
                hw::nvidia_gb200::BiancaBoard {
                    index: hw::nvidia_gb200::BoardIndex::Board1,
                    cpu_serial_number: "0x000000017FFFFFFFFF00000000000002".into(),
                    gpu_serial_number: "165300000002".into(),
                },
            ],
            dpu1: dpus
                .next()
                .expect("Two DPUs must present for GB200 NVL")
                .bluefield3(),
            dpu2: dpus
                .next()
                .expect("Two DPUs must present for GB200 NVL")
                .bluefield3(),
            io_board: [
                hw::nvidia_gb200::IoBoard {
                    index: hw::nvidia_gb200::BoardIndex::Board0,
                    serial_number: "MT0000000001".into(),
                },
                hw::nvidia_gb200::IoBoard {
                    index: hw::nvidia_gb200::BoardIndex::Board1,
                    serial_number: "MT0000000002".into(),
                },
            ],
            topology: hw::nvidia_gbx00::Topology {
                chassis_physical_slot_number: 24,
                compute_tray_index: 14,
                revision_id: 2,
                topology_id: 128,
            },
        }
    }

    fn dgx_gb300_nvl(&self) -> hw::dgx_gb300_nvl::DgxGB300Nvl<'_> {
        let mut dpus = self.dpus.iter();
        // Serials are from the DGX GB300 scrape.
        // GPU_0/1 and GPU_2/3 share a superchip serial; the HGX baseboard
        // (Systems/HGX_Baseboard_0) reports the same serial as the first GPU superchip.
        // The DGX scrape has a single IO board (IO_Board_0); the mock's second slot is
        // a synthetic placeholder.
        let superchip_a_sn = "1642225000100";
        let boards = gb300_boards(
            [
                "0x000000017831E0C9100000000F018200",
                "0x000000017831E0C91000000018018240",
            ],
            [superchip_a_sn, "1642225000086"],
            ["MT2521XZ0GJM", "MT2521XZ0GJM-SYNTH"],
        );
        let mut pool = MacAddressPool::new_pool(self.hw_mac_addr_pool);
        let mut next_mac = || pool.allocate().expect("MAC address must be allocated");
        hw::dgx_gb300_nvl::DgxGB300Nvl {
            system_0_serial_number: "1332425360072".into(),
            chassis_0_serial_number: "1332425360072".into(),
            dpu: dpus
                .next()
                .expect("One DPU must present for DGX GB300 NVL")
                .bluefield3(),
            embedded_1g_nic: hw::nic_intel_i210::NicIntelI210 {
                mac_address: next_mac(),
            },
            bmc_mac_address_eth0: next_mac(),
            bmc_mac_address_eth1: next_mac(),
            bmc_mac_address_usb0: next_mac(),
            hgx_bmc_mac_address_usb0: next_mac(),
            hgx_serial_number: superchip_a_sn.into(),
            topology: hw::nvidia_gbx00::Topology {
                chassis_physical_slot_number: 25,
                compute_tray_index: 15,
                revision_id: 2,
                topology_id: 128,
            },
            cpu: boards.cpu,
            gpu: boards.gpu,
            io_board: boards.io_board,
        }
    }

    fn supermicro_gb300_nvl(&self) -> hw::supermicro_gb300_nvl::SupermicroGB300Nvl<'_> {
        let mut dpus = self.dpus.iter();
        // Serials are from the SMC GB300 tray scrape.
        // GPU_0/1 and GPU_2/3 share a superchip serial; the HGX baseboard
        // (Systems/HGX_Baseboard_0) reports the same serial as the first GPU superchip.
        let superchip_a_sn = "1764625801410";
        let boards = gb300_boards(
            [
                "0x000000017844A04120000000120081C0",
                "0x00000001784191C11000000008018040",
            ],
            [superchip_a_sn, "1764625800673"],
            ["MT2609603LCN", "MT2609603LQ2"],
        );
        let mut pool = MacAddressPool::new_pool(self.hw_mac_addr_pool);
        let mut next_mac = || pool.allocate().expect("MAC address must be allocated");
        hw::supermicro_gb300_nvl::SupermicroGB300Nvl {
            system_0_serial_number: "A978250X6404492".into(),
            chassis_0_serial_number: "HA261S056572".into(),
            dpu: dpus
                .next()
                .expect("One DPU must present for SMC GB300 NVL")
                .bluefield3(),
            embedded_1g_nic: hw::nic_intel_i210::NicIntelI210 {
                mac_address: next_mac(),
            },
            bmc_mac_address_eth0: next_mac(),
            bmc_mac_address_eth1: next_mac(),
            bmc_mac_address_usb0: next_mac(),
            hgx_bmc_mac_address_usb0: next_mac(),
            hgx_serial_number: superchip_a_sn.into(),
            topology: hw::nvidia_gbx00::Topology {
                chassis_physical_slot_number: 25,
                compute_tray_index: 15,
                revision_id: 2,
                topology_id: 128,
            },
            cpu: boards.cpu,
            gpu: boards.gpu,
            io_board: boards.io_board,
        }
    }

    fn lenovo_gb300_nvl(&self) -> hw::lenovo_gb300_nvl::LenovoGB300Nvl<'_> {
        let mut dpus = self.dpus.iter();
        let cpu0_sn = "0x000000017FFFFFFFFF00000000000001";
        let cpu1_sn = "0x000000017FFFFFFFFF00000000000002";
        let superchip_a_sn = "165300000001";
        let superchip_b_sn = "165300000002";
        let io_board0_sn = "MT2524000001";
        let io_board1_sn = "MT2524000002";
        let mut pool = MacAddressPool::new_pool(self.hw_mac_addr_pool);
        let mut next_mac = || pool.allocate().expect("MAC address must be allocated");
        hw::lenovo_gb300_nvl::LenovoGB300Nvl {
            system_0_serial_number: "012345678901234567890123".into(),
            chassis_0_serial_number: Cow::Borrowed(&self.serial),
            dpu: dpus
                .next()
                .expect("One DPU must present for GB300 NVL")
                .bluefield3(),
            embedded_1g_nic: hw::nic_intel_i210::NicIntelI210 {
                mac_address: next_mac(),
            },
            bmc_mac_address_eth0: next_mac(),
            bmc_mac_address_eth1: next_mac(),
            bmc_mac_address_usb0: next_mac(),
            hgx_bmc_mac_address_usb0: next_mac(),
            hgx_serial_number: "012345678901234567890123".into(),
            topology: hw::nvidia_gbx00::Topology {
                chassis_physical_slot_number: 25,
                compute_tray_index: 15,
                revision_id: 2,
                topology_id: 128,
            },
            cpu: [
                hw::nvidia_gb300::NvidiaGB300Cpu {
                    serial_number: cpu0_sn.into(),
                },
                hw::nvidia_gb300::NvidiaGB300Cpu {
                    serial_number: cpu1_sn.into(),
                },
            ],
            gpu: [
                hw::nvidia_gb300::NvidiaGB300Gpu {
                    serial_number: superchip_a_sn.into(),
                },
                hw::nvidia_gb300::NvidiaGB300Gpu {
                    serial_number: superchip_a_sn.into(),
                },
                hw::nvidia_gb300::NvidiaGB300Gpu {
                    serial_number: superchip_b_sn.into(),
                },
                hw::nvidia_gb300::NvidiaGB300Gpu {
                    serial_number: superchip_b_sn.into(),
                },
            ],
            io_board: [
                hw::nvidia_gb300::NvidiaGB300IoBoard {
                    serial_number: io_board0_sn.into(),
                },
                hw::nvidia_gb300::NvidiaGB300IoBoard {
                    serial_number: io_board1_sn.into(),
                },
            ],
        }
    }

    fn liteon_power_shelf(&self) -> hw::liteon_power_shelf::LiteOnPowerShelf<'_> {
        hw::liteon_power_shelf::LiteOnPowerShelf {
            bmc_mac_address: self.bmc_mac_address,
            product_serial_number: Cow::Borrowed(&self.serial),
        }
    }

    fn nvidia_switch_nd5200_ld(&self) -> hw::nvidia_switch_nd5200_ld::NvidiaSwitchNd5200Ld<'_> {
        let mut pool = MacAddressPool::new_pool(self.hw_mac_addr_pool);
        let mut next_mac = || pool.allocate().expect("MAC address must be allocated");
        hw::nvidia_switch_nd5200_ld::NvidiaSwitchNd5200Ld {
            bmc_mac_address_eth0: self.bmc_mac_address,
            bmc_mac_address_eth1: next_mac(),
            bmc_mac_address_usb0: next_mac(),
            bmc_serial_number: Cow::Borrowed(&self.serial),
            switch_serial_number: self
                .switch_serial_number
                .as_deref()
                .unwrap_or(&self.serial)
                .into(),
        }
    }

    fn nvidia_dgx_h100(&self) -> hw::nvidia_dgx_h100::NvidiaDgxH100<'_> {
        let mut pool = MacAddressPool::new_pool(self.hw_mac_addr_pool);
        let mut next_mac = || pool.allocate().expect("MAC address must be allocated");
        let storage_nic0_p0_mac = next_mac();
        let storage_nic0_serial = format!("MT{}", storage_nic0_p0_mac.to_string().replace(":", ""));
        hw::nvidia_dgx_h100::NvidiaDgxH100 {
            dgx_system_serial_number: Cow::Borrowed(&self.serial),
            dgx_chassis_serial_number: Cow::Borrowed("1663223000002"),
            ib_nics: [
                hw::nic_nvidia_cx7::NicNvidiaCx7B {
                    serial_number: "MT2307X00001".into(),
                    mac_addresses: [(); _].map(|_| next_mac()),
                },
                hw::nic_nvidia_cx7::NicNvidiaCx7B {
                    serial_number: "MT2307X00002".into(),
                    mac_addresses: [(); _].map(|_| next_mac()),
                },
            ],
            mgmt_nic: hw::nic_intel_x550::NicIntelX550 {
                mac_address: next_mac(),
            },
            storage_nic0: hw::nic_nvidia_cx7::NicNvidiaCx7A {
                serial_number: storage_nic0_serial.into(),
                mac_addresses: [(); _].map(|_| next_mac()),
            },
            storage_nic1: hw::nic_intel_e810::NicIntelE810 {
                mac_addresses: [(); _].map(|_| next_mac()),
            },
            dpu: self
                .dpus
                .first()
                .expect("Single DPUs must present for H100")
                .bluefield3(),
            gpu_serial: [
                "1652900000001".into(),
                "1652900000002".into(),
                "1652900000003".into(),
                "1652900000004".into(),
                "1652900000005".into(),
                "1652900000006".into(),
                "1652900000007".into(),
                "1652900000008".into(),
            ],
            bmc_mac_address_eth0: next_mac(),
            bmc_mac_address_usb0: next_mac(),
            hgx_bmc_mac_address_usb0: next_mac(),
        }
    }

    fn generic_server(&self) -> hw::generic_ami::GenericAmi<'_> {
        let nics = self
            .dpus
            .iter()
            .enumerate()
            .map(|(index, dpu)| (index + 1, dpu.bluefield3().host_nic()))
            .collect();

        hw::generic_ami::GenericAmi {
            product_serial_number: Cow::Borrowed(&self.serial),
            nics,
        }
    }
}

impl MachineInfo {
    pub fn oem_state(&self) -> redfish::oem::State {
        match self {
            MachineInfo::Host(host) => host.oem_state(),
            MachineInfo::Dpu(dpu) => redfish::oem::State::NvidiaBluefield(
                redfish::oem::nvidia::bluefield::BluefieldState::new(
                    dpu.settings.nic_mode,
                    dpu.host_mac_address,
                ),
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
            MachineInfo::Dpu(_) => {
                redfish::oem::BmcVendor::Nvidia(redfish::oem::NvidiaNamestyle::Capitalized)
            }
        }
    }

    pub fn bmc_redfish_version(&self) -> &'static str {
        match self {
            MachineInfo::Host(h) => h.bmc_redfish_version(),
            MachineInfo::Dpu(_) => "1.17.0",
        }
    }

    pub fn bmc_product(&self) -> Option<&'static str> {
        match self {
            MachineInfo::Host(h) => h.bmc_product(),
            MachineInfo::Dpu(_) => Some("BlueField-3 DPU"),
        }
    }

    pub fn system_config(
        &self,
        callbacks: Arc<dyn crate::Callbacks>,
    ) -> redfish::computer_system::Config {
        match self {
            MachineInfo::Host(host) => host.system_config(callbacks),
            MachineInfo::Dpu(dpu) => dpu.bluefield3().system_config(callbacks),
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

    pub fn discovery_info(&self) -> rpc::machine_discovery::DiscoveryInfo {
        match self {
            Self::Host(h) => h.discovery_info(),
            Self::Dpu(dpu) => dpu.bluefield3().discovery_info(),
        }
    }

    pub fn factory_default_account(&self) -> redfish::account_service::Account {
        match self {
            MachineInfo::Host(h) => h.factory_default_account(),
            MachineInfo::Dpu(_) => redfish::account_service::Account::administrator(
                "root",
                DUMMY_FACTORY_USERNAME,
                DUMMY_FACTORY_DPU_PASSWORD,
            ),
        }
    }
}

/// CPU / GPU / IO-board chassis common to every GB300 tray: NVIDIA HGX reference
/// silicon, identical in shape across ODMs (only the serials differ per scrape).
/// GPU_0/1 and GPU_2/3 each share a superchip serial.
struct Gb300Boards<'a> {
    cpu: [hw::nvidia_gb300::NvidiaGB300Cpu<'a>; 2],
    gpu: [hw::nvidia_gb300::NvidiaGB300Gpu<'a>; 4],
    io_board: [hw::nvidia_gb300::NvidiaGB300IoBoard<'a>; 2],
}

fn gb300_boards<'a>(
    cpu_serials: [&'a str; 2],
    superchip_serials: [&'a str; 2],
    io_board_serials: [&'a str; 2],
) -> Gb300Boards<'a> {
    let [cpu0, cpu1] = cpu_serials;
    let [superchip_a, superchip_b] = superchip_serials;
    let [io0, io1] = io_board_serials;
    Gb300Boards {
        cpu: [
            hw::nvidia_gb300::NvidiaGB300Cpu {
                serial_number: cpu0.into(),
            },
            hw::nvidia_gb300::NvidiaGB300Cpu {
                serial_number: cpu1.into(),
            },
        ],
        gpu: [
            hw::nvidia_gb300::NvidiaGB300Gpu {
                serial_number: superchip_a.into(),
            },
            hw::nvidia_gb300::NvidiaGB300Gpu {
                serial_number: superchip_a.into(),
            },
            hw::nvidia_gb300::NvidiaGB300Gpu {
                serial_number: superchip_b.into(),
            },
            hw::nvidia_gb300::NvidiaGB300Gpu {
                serial_number: superchip_b.into(),
            },
        ],
        io_board: [
            hw::nvidia_gb300::NvidiaGB300IoBoard {
                serial_number: io0.into(),
            },
            hw::nvidia_gb300::NvidiaGB300IoBoard {
                serial_number: io1.into(),
            },
        ],
    }
}
