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

use carbide_network::{deserialize_input_mac_to_address, is_locally_administered_mac};
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
use tokio::sync::Semaphore;

use crate::{Error, limited};

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
    pub async fn explore(
        manager: Manager<B>,
        config: &Config,
        limiter: &Semaphore,
    ) -> Result<Self, Error<B>> {
        // The ethernet-interface, host-interface, and OEM subtrees of one
        // manager are independent, so they proceed concurrently.
        let eth_interfaces_branch = async {
            let collection = limited(limiter, manager.ethernet_interfaces())
                .await
                .map_err(Error::nv_redfish("manager ethernet interfaces"))?
                .ok_or_else(Error::bmc_not_provided("manager ethernet interfaces"))?;
            limited(limiter, collection.members())
                .await
                .map_err(Error::nv_redfish("manager ethernet interfaces members"))
        };

        let host_interfaces_branch = async {
            if config.need_host_interfaces {
                if let Some(collection) = limited(limiter, manager.host_interfaces())
                    .await
                    .map_err(Error::nv_redfish("host interfaces collection"))?
                {
                    Ok(Some(limited(limiter, collection.members()).await.map_err(
                        Error::nv_redfish("host interfaces collection members"),
                    )?))
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        };

        let oem_dell_attributes_branch = async {
            if config.need_oem_dell_attributes {
                limited(limiter, manager.oem_dell_attributes())
                    .await
                    .map_err(Error::nv_redfish("Dell OEM Attributes"))
            } else {
                Ok(None)
            }
        };

        let oem_lenovo_security_service_branch = async {
            if config.need_oem_lenovo_security_service
                && let Some(oem_lenovo) = manager
                    .oem_lenovo()
                    .map_err(Error::nv_redfish("Lenovo manager OEM"))?
            {
                limited(limiter, oem_lenovo.security())
                    .await
                    .map_err(Error::nv_redfish("Lenovo OEM security service"))
            } else {
                Ok(None)
            }
        };

        let oem_supermicro_branch = async {
            if (config.need_oem_supermicro_kcs_interface || config.need_oem_supermicro_sys_lockdown)
                && let Some(oem_supermicro) = manager
                    .oem_supermicro()
                    .map_err(Error::nv_redfish("Supermicro OEM"))?
            {
                let kcs_interface_branch = async {
                    if config.need_oem_supermicro_kcs_interface {
                        limited(limiter, oem_supermicro.kcs_interface())
                            .await
                            .map_err(Error::nv_redfish("Supermicro KCS Interface"))
                    } else {
                        Ok(None)
                    }
                };
                let sys_lockdown_branch = async {
                    if config.need_oem_supermicro_sys_lockdown {
                        limited(limiter, oem_supermicro.sys_lockdown())
                            .await
                            .map_err(Error::nv_redfish("Supermicro SysLockdown"))
                    } else {
                        Ok(None)
                    }
                };
                tokio::try_join!(kcs_interface_branch, sys_lockdown_branch)
            } else {
                Ok((None, None))
            }
        };

        let oem_ami_config_bmc_branch = async {
            if config.need_oem_ami_config_bmc {
                limited(limiter, manager.oem_ami_config_bmc())
                    .await
                    .map_err(Error::nv_redfish("AMI manager ConfigBMC OEM"))
            } else {
                Ok(None)
            }
        };

        let (
            eth_interfaces,
            host_interfaces,
            oem_dell_attributes,
            oem_lenovo_security_service,
            (oem_supermicro_kcs_interface, oem_supermicro_sys_lockdown),
            oem_ami_config_bmc,
        ) = tokio::try_join!(
            eth_interfaces_branch,
            host_interfaces_branch,
            oem_dell_attributes_branch,
            oem_lenovo_security_service_branch,
            oem_supermicro_branch,
            oem_ami_config_bmc_branch,
        )?;

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

            // Warn if the manager eth0 MAC is locally-administered: a real BMC MAC is
            // globally unique, so this signals transient pre-sync data (seen briefly
            // after a BMC reboot) that would poison anything keyed on the BMC MAC.
            if iface.id().inner().eq_ignore_ascii_case("eth0")
                && let Some(mac) = mac_address
                && is_locally_administered_mac(mac)
            {
                tracing::warn!(
                    manager_id = %self.manager.id().inner(),
                    eth0_mac = %mac,
                    "manager eth0 MAC is locally-administered (transient pre-sync data?)",
                );
            }

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
