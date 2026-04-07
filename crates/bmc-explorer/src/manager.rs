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

use std::str::FromStr;

use carbide_network::deserialize_input_mac_to_address;
use model::site_explorer::{
    EthernetInterface as ModelEthernetInterface, Manager as ModelManager, UefiDevicePath,
};
use nv_redfish::ethernet_interface::EthernetInterface;
use nv_redfish::host_interface::HostInterface;
use nv_redfish::manager::Manager;
use nv_redfish::oem::ami::config_bmc::ConfigBmc;
use nv_redfish::oem::dell::attributes::DellAttributes;
use nv_redfish::oem::lenovo::security_service::LenovoSecurityService;
use nv_redfish::oem::supermicro::{KcsInterface, SysLockdown};
use nv_redfish::{Bmc, Resource};

use crate::Error;

#[derive(Default)]
pub struct Config {
    pub need_host_interfaces: bool,
    pub need_oem_dell_attributes: bool,
    pub need_oem_lenovo_security_service: bool,
    pub need_oem_supermicro_kcs_interface: bool,
    pub need_oem_supermicro_sys_lockdown: bool,
    pub need_oem_ami_config_bmc: bool,
}

pub struct ExploredManager<B: Bmc> {
    pub manager: Manager<B>,
    pub eth_interfaces: Vec<EthernetInterface<B>>,
    pub host_interfaces: Option<Vec<HostInterface<B>>>,
    pub oem_dell_attributes: Option<DellAttributes<B>>,
    pub oem_lenovo_security_service: Option<LenovoSecurityService<B>>,
    pub oem_supermicro_kcs_interface: Option<KcsInterface<B>>,
    pub oem_supermicro_sys_lockdown: Option<SysLockdown<B>>,
    pub oem_ami_config_bmc: Option<ConfigBmc<B>>,
}

impl<B: Bmc> ExploredManager<B> {
    pub async fn explore(manager: Manager<B>, config: &Config) -> Result<Self, Error<B>> {
        let eth_interfaces = manager
            .ethernet_interfaces()
            .await
            .map_err(Error::nv_redfish("manager ethernet interfaces"))?
            .ok_or_else(Error::bmc_not_provided("manager ethernet interfaces"))?
            .members()
            .await
            .map_err(Error::nv_redfish("manager ethernet interfaces members"))?;

        let host_interfaces = if config.need_host_interfaces {
            if let Some(collection) = manager
                .host_interfaces()
                .await
                .map_err(Error::nv_redfish("host interfaces collection"))?
            {
                Some(
                    collection
                        .members()
                        .await
                        .map_err(Error::nv_redfish("host interfaces collection members"))?,
                )
            } else {
                None
            }
        } else {
            None
        };

        let oem_dell_attributes = if config.need_oem_dell_attributes {
            manager
                .oem_dell_attributes()
                .await
                .map_err(Error::nv_redfish("Dell OEM Attributes"))?
        } else {
            None
        };

        let oem_lenovo_security_service = if config.need_oem_lenovo_security_service
            && let Some(oem_lenovo) = manager
                .oem_lenovo()
                .map_err(Error::nv_redfish("Lenovo manager OEM"))?
        {
            oem_lenovo
                .security()
                .await
                .map_err(Error::nv_redfish("Lenovo OEM security service"))?
        } else {
            None
        };

        let mut oem_supermicro_kcs_interface = None;
        let mut oem_supermicro_sys_lockdown = None;
        if (config.need_oem_supermicro_kcs_interface || config.need_oem_supermicro_sys_lockdown)
            && let Some(oem_supermicro) = manager
                .oem_supermicro()
                .map_err(Error::nv_redfish("Supermicro OEM"))?
        {
            if config.need_oem_supermicro_kcs_interface {
                oem_supermicro_kcs_interface = oem_supermicro
                    .kcs_interface()
                    .await
                    .map_err(Error::nv_redfish("Supermicro KCS Interface"))?
            };

            if config.need_oem_supermicro_sys_lockdown {
                oem_supermicro_sys_lockdown = oem_supermicro
                    .sys_lockdown()
                    .await
                    .map_err(Error::nv_redfish("Supermicro SysLockdown"))?
            }
        }

        let oem_ami_config_bmc = if config.need_oem_ami_config_bmc {
            manager
                .oem_ami_config_bmc()
                .await
                .map_err(Error::nv_redfish("AMI manager ConfigBMC OEM"))?
        } else {
            None
        };

        Ok(Self {
            manager,
            eth_interfaces,
            host_interfaces,
            oem_dell_attributes,
            oem_lenovo_security_service,
            oem_supermicro_kcs_interface,
            oem_supermicro_sys_lockdown,
            oem_ami_config_bmc,
        })
    }

    pub fn to_model(&self) -> Result<ModelManager, Error<B>> {
        let ethernet_interfaces = self.eth_interfaces.iter().map(|iface| {
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
                .map(UefiDevicePath::from_str)
                .transpose()
                .map_err(|err| Error::InvalidValue(format!("UefiDevicePath: {err}")))?;

            Ok(ModelEthernetInterface {
                description: iface.description().map(|v| v.to_string()),
                id: Some(iface.id().to_string()),
                interface_enabled: iface.interface_enabled(),
                mac_address,
                link_status: iface.link_status().map(|s| format!("{s:?}")),
                uefi_device_path,
            })
        }).collect::<Result<Vec<_>, _>>()?;

        Ok(ModelManager {
            id: self.manager.id().inner().to_string(),
            ethernet_interfaces,
        })
    }
}
