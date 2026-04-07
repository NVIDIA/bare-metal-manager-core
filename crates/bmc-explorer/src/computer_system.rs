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

use std::convert::identity;
use std::str::FromStr;

use carbide_network::{deserialize_input_mac_to_address, sanitized_mac};
use mac_address::MacAddress;
use model::site_explorer::{
    BootOption as ModelBootOption, BootOrder as ModelBootOrder,
    ComputerSystem as ModelComputerSystem, ComputerSystemAttributes,
    EthernetInterface as ModelEthernetInterface, MachineSetupDiff, NicMode, PCIeDevice,
    PowerState as ModelPowerState, SecureBootStatus, UefiDevicePath as ModelUefiDevicePath,
};
use nv_redfish::computer_system::boot_option::UefiDevicePath as BootOptionUefiDevicePath;
use nv_redfish::computer_system::{
    Bios, BootOption, ComputerSystem, SecureBoot, SecureBootCurrentBootType,
};
use nv_redfish::ethernet_interface::{EthernetInterface, UefiDevicePath as EthUefiDevicePath};
use nv_redfish::oem::nvidia::bluefield::NvidiaComputerSystem;
use nv_redfish::pcie_device::PcieDevice;
use nv_redfish::resource::PowerState;
use nv_redfish::{Bmc, Resource, ResourceProvidesStatus};
use regex::Regex;

use crate::{Error, ExploredChassisCollection, compare_boot_options, hw};

const UEFI_MAC_PATTERN_CAPTURE: &str = "mac";
lazy_static::lazy_static! {
    static ref UEFI_MAC_PATTERN: Regex = Regex::new(&format!(r"MAC\((?<{UEFI_MAC_PATTERN_CAPTURE}>[[:alnum:]]+)\,")).unwrap();
}

pub struct Config {
    pub need_oem_nvidia_bluefield: bool,
}

pub struct ExploredComputerSystem<B: Bmc> {
    pub system: ComputerSystem<B>,
    pub bios: Option<Bios<B>>,
    pub boot_options: Vec<BootOption<B>>,
    pub ethernet_interfaces: Vec<EthernetInterface<B>>,
    pub oem_nvidia_bluefield: Option<NvidiaComputerSystem<B>>,
    pub secure_boot: Option<SecureBoot<B>>,
}

impl<B: Bmc> ExploredComputerSystem<B> {
    pub async fn explore(system: ComputerSystem<B>, config: &Config) -> Result<Self, Error<B>> {
        let boot_options = if let Some(collection) = system
            .boot_options()
            .await
            .map_err(Error::nv_redfish("boot options"))?
        {
            collection
                .members()
                .await
                .map_err(Error::nv_redfish("boot options members"))?
        } else {
            vec![]
        };

        let bios = system.bios().await.map_err(Error::nv_redfish("bios"))?;

        let ethernet_interfaces = match system.ethernet_interfaces().await {
            Ok(Some(ifaces)) => ifaces
                .members()
                .await
                .map_err(Error::nv_redfish("system ethernet interfaces members"))?,
            Ok(None) => vec![],
            Err(err) => Err(Error::NvRedfish {
                context: "system ethernet interfaces",
                err,
            })?,
        };

        let oem_nvidia_bluefield = if config.need_oem_nvidia_bluefield {
            system
                .oem_nvidia_bluefield()
                .await
                .map_err(Error::nv_redfish("NVIDIA system Bluefield OEM"))?
        } else {
            None
        };

        let secure_boot = system
            .secure_boot()
            .await
            .map_err(Error::nv_redfish("secure boot"))?;

        Ok(Self {
            system,
            bios,
            boot_options,
            ethernet_interfaces,
            oem_nvidia_bluefield,
            secure_boot,
        })
    }

    pub fn to_model(
        &self,
        hw_type: Option<hw::HwType>,
        chassis: &ExploredChassisCollection<B>,
        pcie_devices: &[PcieDevice<B>],
    ) -> Result<ModelComputerSystem, Error<B>> {
        let hw_id = self.system.hardware_id();
        let is_dpu = hw_type == Some(hw::HwType::Bluefield);
        let ethernet_interfaces = self.ethernet_interfaces(hw_type)?;

        let mut base_mac = None;
        let mut nic_mode = None;
        let mut serial_number = hw_id.serial_number.map(|v| v.into_inner());
        if is_dpu {
            // This part processes dpu case and do two things such as
            // 1. update system serial_number in case it is empty using chassis serial_number
            // 2. format serial_number data using the same rules as in fetch_chassis()
            if serial_number.is_none() {
                serial_number = chassis.dpu_card1_serial_number()?;
            }

            if let Some(oem_bf) = &self.oem_nvidia_bluefield {
                base_mac = oem_bf.base_mac().and_then(|v| {
                    v.inner()
                        .parse()
                        .inspect_err(|err| {
                            tracing::warn!("Failed to parse BaseMAC: {err} (mac: {v})");
                        })
                        .ok()
                });
                nic_mode = Self::dpu_mode(&self.system, self.bios.as_ref(), oem_bf);
            }
        }

        let boot_order = self.system.boot_order().map(|order| ModelBootOrder {
            boot_order: order
                .iter()
                .filter_map(|boot_ref| {
                    self.boot_options
                        .iter()
                        .find(|opt| opt.boot_reference() == *boot_ref)
                        .map(|opt| ModelBootOption {
                            id: opt.id().to_string(),
                            display_name: opt
                                .display_name()
                                .map(|v| v.to_string())
                                .unwrap_or("".into()),
                            uefi_device_path: opt.uefi_device_path().map(|v| v.to_string()),
                            boot_option_enabled: opt.enabled(),
                        })
                })
                .collect(),
        });

        let is_infinite_boot_enabled = hw_type
            .and_then(|hw_type| hw_type.infinite_boot_enabled_attr())
            .and_then(|attr| self.bios_attr_eq(&attr));

        let pcie_devices = pcie_devices
            .iter()
            .filter_map(|dev| pcie_device_to_model(hw_type, dev))
            .collect();

        Ok(ModelComputerSystem {
            ethernet_interfaces,
            id: self.system.id().to_string(),
            manufacturer: hw_id.manufacturer.map(|v| v.to_string()),
            model: hw_id.model.map(|v| v.to_string()),
            serial_number: serial_number.map(|v| v.to_string()),
            attributes: ComputerSystemAttributes {
                nic_mode,
                is_infinite_boot_enabled,
            },
            pcie_devices,
            base_mac,
            power_state: self
                .system
                .power_state()
                .map(|v| match v {
                    PowerState::On => ModelPowerState::On,
                    PowerState::Off => ModelPowerState::Off,
                    PowerState::PoweringOn => ModelPowerState::PoweringOn,
                    PowerState::PoweringOff => ModelPowerState::PoweringOff,
                    PowerState::Paused => ModelPowerState::Paused,
                })
                .unwrap_or_default(),
            sku: self.system.sku().map(|v| v.to_string()),
            boot_order,
        })
    }

    pub fn secure_boot_status(&self) -> Result<SecureBootStatus, Error<B>> {
        let secure_boot = self
            .secure_boot
            .as_ref()
            .ok_or_else(Error::bmc_not_provided("SecureBoot resource"))?;
        let enabled = secure_boot
            .secure_boot_enable()
            .ok_or_else(Error::bmc_not_provided(
                "SecureBootEnable in SecureBoot resource",
            ))?;
        let current_boot =
            secure_boot
                .secure_boot_current_boot()
                .ok_or_else(Error::bmc_not_provided(
                    "SecureBootCurrentBootType in SecureBoot resource",
                ))?;
        Ok(SecureBootStatus {
            is_enabled: enabled && current_boot == SecureBootCurrentBootType::Enabled,
        })
    }

    pub fn boot_order_first_option(&self) -> Option<&BootOption<B>> {
        self.system
            .boot_order()
            .as_ref()
            .and_then(|v| v.first())
            .and_then(|actual_ref| {
                self.boot_options
                    .iter()
                    .find(|opt| opt.boot_reference() == *actual_ref)
            })
    }

    pub fn check_boot_by_uefi_prefix(
        &self,
        boot_interface_mac: MacAddress,
    ) -> Option<MachineSetupDiff> {
        let expected = self
            // Find UEFI device path of the ethernet interface
            // that has boot_interface_mac MAC address.
            .ethernet_interfaces
            .iter()
            .find(|eth| {
                eth.mac_address()
                    .map(|v| {
                        v.as_str()
                            .parse::<MacAddress>()
                            .is_ok_and(|v| v == boot_interface_mac)
                    })
                    .is_some_and(identity)
            })
            .and_then(|eth| eth.uefi_device_path())
            // Find boot option that starts with correponding
            // UEFI device path.
            .and_then(|eth_uefi_device_path| {
                self.boot_options.iter().find(|opt| {
                    opt.uefi_device_path().is_some_and(|path| {
                        is_uefi_tree_child(eth_uefi_device_path, path)
                            && path.inner().contains("/IPv4(")
                    })
                })
            });

        // Find actual option that is first in boot_order.
        let actual = self.boot_order_first_option();
        compare_boot_options(expected, actual)
    }

    fn ethernet_interfaces(
        &self,
        hw_type: Option<hw::HwType>,
    ) -> Result<Vec<ModelEthernetInterface>, Error<B>> {
        let mut result = self.ethernet_interfaces.iter()
            .map(|iface| {
                let mac_address = iface
                    .mac_address()
                    .map(|addr| {
                        deserialize_input_mac_to_address(addr.as_str())
                            .map_err(|e| Error::InvalidValue(format!("MAC address not valid: {addr} (err: {e})")))
                    })
                    .transpose()
                    .or_else(|err| {
                        if iface
                            .interface_enabled().is_some_and(|is_enabled| !is_enabled)
                        {
                            // disabled interfaces sometimes populate the MAC address with junk,
                            // ignore this error and create the interface with an empty mac address
                            // in the exploration report
                            tracing::debug!(
                                "could not parse MAC address for a disabled interface {} (link_status: {:#?}): {err}",
                                iface.id(), iface.link_status()
                            );
                            Ok(None)
                        } else {
                            Err(err)
                        }
                    })?;

                let uefi_device_path = iface
                    .uefi_device_path()
                    .map(|v| v.into_inner())
                    .map(ModelUefiDevicePath::from_str)
                    .transpose()
                    .map_err(|err| Error::InvalidValue(format!("UefiDevicePath: {err}")))?;

                Ok(ModelEthernetInterface {
                    description: iface.description().map(|d| d.to_string()),
                    id: Some(iface.id().to_string()),
                    interface_enabled: iface.interface_enabled(),
                    mac_address,
                    link_status: iface.link_status().map(|s| format!("{s:?}")),
                    uefi_device_path,
                })
            }).collect::<Result<Vec<_>, _>>()?;

        if hw_type.is_some_and(|v| v == hw::HwType::Bluefield)
            && !result.iter().any(|iface| {
                iface
                    .id
                    .as_ref()
                    .is_some_and(|v| v.to_lowercase().contains("oob"))
            })
        {
            // For Bluefield without OOB interface we craft ethernet
            // interface from boot options as workaround.
            if let Some(oob_iface) = self.oob_interface_from_boot_options()? {
                result.push(oob_iface);
            } else {
                tracing::warn!("Error getting OOB interface for the DPU");
            }
        }
        Ok(result)
    }

    fn oob_interface_from_boot_options(&self) -> Result<Option<ModelEthernetInterface>, Error<B>> {
        // Temporary workaround until oob mac would be possible to get via Redfish
        self.boot_options
            .iter()
            .find_map(|boot_opt| {
                // display_name: "NET-OOB-IPV4"
                if boot_opt
                    .display_name()
                    .is_some_and(|v| v.inner().contains("OOB"))
                {
                    boot_opt
                        .uefi_device_path()
                        .and_then(|path| UEFI_MAC_PATTERN.captures(path.inner()))
                } else {
                    None
                }
            })
            .and_then(|captures| captures.name(UEFI_MAC_PATTERN_CAPTURE))
            .map(|mac_capture| {
                sanitized_mac(mac_capture.as_str())
                    .map_err(|e| {
                        Error::InvalidValue(format!(
                            "MAC address not valid: {} (err: {e})",
                            mac_capture.as_str()
                        ))
                    })
                    .map(|mac_addr| ModelEthernetInterface {
                        description: Some("1G DPU OOB network interface".to_string()),
                        id: Some("oob_net0".to_string()),
                        interface_enabled: None,
                        mac_address: Some(mac_addr),
                        link_status: None,
                        uefi_device_path: None,
                    })
            })
            .transpose()
    }

    fn dpu_mode(
        system: &ComputerSystem<B>,
        bios: Option<&Bios<B>>,
        bf_ncs: &NvidiaComputerSystem<B>,
    ) -> Option<NicMode> {
        let hw_id = system.hardware_id();
        let manufacturer = hw_id.manufacturer.map(|v| v.into_inner());
        let model = hw_id.model.map(|v| v.into_inner());
        match manufacturer {
            None | Some("Nvidia") | Some("https://www.mellanox.com") => {
                match model {
                    None
                    | Some("BlueField-3 DPU")
                    | Some("Bluefield 3 DPU")
                    | Some("BlueField-3 SmartNIC Main Card")
                    | Some("Bluefield 3 SmartNIC Main Card") => {
                        use nv_redfish::oem::nvidia::bluefield::nvidia_computer_system::Mode;
                        bf_ncs.mode().map(|v| match v {
                            Mode::DpuMode => NicMode::Dpu,
                            Mode::NicMode => NicMode::Nic,
                        })
                    }
                    Some("Bluefield 2 SmartNIC Main Card") | Some("Bluefield SoC") => {
                        // Get from bios
                        bios.and_then(|bios| bios.attribute("NicMode"))
                            .and_then(|attr| {
                                attr.str_value().and_then(|v| match v {
                                    "NicMode" => Some(NicMode::Nic),
                                    "DpuMode" => Some(NicMode::Dpu),
                                    _ => None,
                                })
                            })
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    pub fn bios_attr_eq(&self, expected: &hw::BiosAttr) -> Option<bool> {
        self.bios
            .as_ref()
            .and_then(|bios| bios.attribute(expected.key))
            .map(|actual| match expected.value {
                hw::BiosAttrValue::Str(v) => actual.str_value() == Some(v),
                hw::BiosAttrValue::Bool(v) => actual.bool_value() == Some(v),
                hw::BiosAttrValue::Int(v) => actual.integer_value() == Some(v),
                hw::BiosAttrValue::AnyStr(v) => v.iter().any(|v| actual.str_value() == Some(v)),
            })
    }

    pub fn verify_bios_attr(&self, expected: &hw::BiosAttr<'_>) -> Option<MachineSetupDiff> {
        if let Some(actual) = self
            .bios
            .as_ref()
            .and_then(|bios| bios.attribute(expected.key))
            && !match expected.value {
                hw::BiosAttrValue::Bool(v) => actual.bool_value() == Some(v),
                hw::BiosAttrValue::Str(v) => actual.str_value() == Some(v),
                hw::BiosAttrValue::Int(v) => actual.integer_value() == Some(v),
                hw::BiosAttrValue::AnyStr(v) => v.iter().any(|v| actual.str_value() == Some(v)),
            }
        {
            Some(MachineSetupDiff {
                key: expected.key.to_string(),
                expected: expected.value.to_string(),
                actual: actual
                    .str_value()
                    .map(|v| v.to_string())
                    .or_else(|| actual.bool_value().map(|v| v.to_string()))
                    .or_else(|| actual.integer_value().map(|v| v.to_string()))
                    .unwrap_or_else(|| "unexpected type".to_string()),
            })
        } else {
            None
        }
    }
}

fn is_uefi_tree_child(
    parent: EthUefiDevicePath<&str>,
    child: BootOptionUefiDevicePath<&str>,
) -> bool {
    let child_str = child.inner();
    let parent_str = parent.inner();
    // Here is exampl of child path:
    // "PciRoot(0x0)/Pci(0x10,0x0)/Pci(0x0,0x0)/MAC(5CFF35FE04BC,0x1)/IPv4(0.0.0.0,0x0,DHCP,0.0.0.0,0.0.0.0,0.0.0.0)/Uri()"
    // With root path:
    // "PciRoot(0x0)/Pci(0x10,0x0)/Pci(0x0,0x0)
    //
    // Also HPE can provide Acpi(0x00168E09,0x3)/Pci(0x10,0x0)/Pci(0x0,0x0)/...
    // instead of PciRoot(0x3)/Pci(0x10,0x0)/Pci(0x0,0x0)
    const HPE_ACPI_PREFIX: &str = "Acpi(0x00168E09,";
    const PCI_ROOT_PREFIX: &str = "PciRoot(";

    if child_str.starts_with(HPE_ACPI_PREFIX) && parent_str.starts_with(PCI_ROOT_PREFIX) {
        child_str[HPE_ACPI_PREFIX.len()..].starts_with(&parent_str[PCI_ROOT_PREFIX.len()..])
    } else {
        child_str.starts_with(parent_str)
    }
}

fn pcie_device_to_model<B: Bmc>(
    hw_type: Option<hw::HwType>,
    dev: &PcieDevice<B>,
) -> Option<PCIeDevice> {
    let hw_id = dev.hardware_id();
    let status = dev.status();
    hw_id.manufacturer?;
    if status.as_ref().is_some_and(|s| {
        s.state
            .is_some_and(|v| v != nv_redfish::resource::State::Enabled)
    }) {
        return None;
    }

    Some(PCIeDevice {
        description: dev.description().map(|v| v.to_string()),
        firmware_version: dev.firmware_version().map(|v| v.to_string()),
        id: Some(dev.id().to_string()),
        manufacturer: hw_id.manufacturer.map(|v| v.to_string()),
        // TODO: In old model it is dev.gpu_vendor, but it is not
        // standard. It can be taken from
        // .Oem.Supermicro.GPUDevice.GPUVendor for Supermicro but it
        // was never implemented.
        gpu_vendor: None,
        name: Some(dev.name().to_string()),
        part_number: hw_id.part_number.map(|v| v.to_string()),
        // Trim of serial_number is added because serial number of DPU
        // contains trailing spaces... Probably, it should be code
        // specific for DPU...
        serial_number: hw_id.serial_number.map(|v| {
            if hw_type == Some(hw::HwType::Hpe) {
                // TODO: This is how it is implemented in
                // libredfish. I'm quite sure that it should be same
                // way for all vendors but is unknown if it safe to
                // change
                v.inner().trim().to_string()
            } else {
                v.inner().to_string()
            }
        }),
        // TODO: Should not be converted to string....
        status: status.map(|status| model::site_explorer::SystemStatus {
            health: status.health.map(|v| {
                match v {
                    nv_redfish::resource::Health::Ok => "OK",
                    nv_redfish::resource::Health::Warning => "Warning",
                    nv_redfish::resource::Health::Critical => "Critical",
                }
                .into()
            }),
            health_rollup: status.health_rollup.map(|v| {
                match v {
                    nv_redfish::resource::Health::Ok => "OK",
                    nv_redfish::resource::Health::Warning => "Warning",
                    nv_redfish::resource::Health::Critical => "Critical",
                }
                .into()
            }),
            // Not enabled devices are filtered by code above.
            state: status
                .state
                .map(|_| "Enabled".to_string())
                .unwrap_or("".into()),
        }),
    })
}
