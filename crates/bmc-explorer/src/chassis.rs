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
use std::fmt;

use carbide_network::BaseMac;
use futures::stream::{self, StreamExt, TryStreamExt};
use itertools::Itertools;
use mac_address::MacAddress;
use model::site_explorer::{Chassis, PowerState as ModelPowerState};
use nv_redfish::assembly::Model as AssemblyModel;
use nv_redfish::chassis::Chassis as NvChassis;
use nv_redfish::core::ODataId;
use nv_redfish::hardware_id::{Manufacturer, Model};
use nv_redfish::pcie_device::PcieDevice;
use nv_redfish::resource::ResourceIdRef;
use nv_redfish::{Bmc, Resource, ServiceRoot};
use tokio::sync::Semaphore;

use crate::network_adapter::ExploredNetworkAdapterCollection;
use crate::{DEFAULT_MAX_CONCURRENT_BMC_REQUESTS, Error, limited, network_adapter};

type AssemblyModelFilterFn = fn(Option<AssemblyModel<&str>>) -> bool;
const BF4_NDF0_TO_BASE_MAC_OFFSET: u64 = 0x10;
pub struct Config {
    pub network_adapter: network_adapter::Config,
    pub need_assembly_sn: fn(ResourceIdRef) -> Option<AssemblyModelFilterFn>,
    pub lazy_fetch: Option<fn(&ODataId) -> bool>,
}

pub struct ExploredChassisCollection<B: Bmc> {
    pub members: Vec<ExploredChassis<B>>,
}

impl<B: Bmc> ExploredChassisCollection<B> {
    pub async fn explore(
        root: &ServiceRoot<B>,
        config: &Config,
        limiter: &Semaphore,
    ) -> Result<Self, Error<B>> {
        let members = stream::iter(Self::fetch_members(root, config, limiter).await?)
            .map(|m| ExploredChassis::explore(m, config, limiter))
            .buffered(DEFAULT_MAX_CONCURRENT_BMC_REQUESTS)
            .try_collect()
            .await?;
        Ok(Self { members })
    }

    async fn fetch_members(
        root: &ServiceRoot<B>,
        config: &Config,
        limiter: &Semaphore,
    ) -> Result<Vec<NvChassis<B>>, Error<B>> {
        if let Some(filter) = config.lazy_fetch {
            let links = limited(limiter, root.chassis_links())
                .await
                .map_err(Error::nv_redfish("chassis collection"))?
                .ok_or_else(Error::bmc_not_provided("chassis collection"))?;
            stream::iter(links.into_iter().filter(|l| filter(l.odata_id())))
                .map(|l| async move {
                    limited(limiter, l.upgrade())
                        .await
                        .map_err(Error::nv_redfish("chassis collection member"))
                })
                .buffered(DEFAULT_MAX_CONCURRENT_BMC_REQUESTS)
                .try_collect()
                .await
        } else {
            let collection = limited(limiter, root.chassis())
                .await
                .map_err(Error::nv_redfish("chassis collection"))?
                .ok_or_else(Error::bmc_not_provided("chassis collection"))?;
            limited(limiter, collection.members())
                .await
                .map_err(Error::nv_redfish("chassis collection members"))
        }
    }

    pub fn to_model(&self) -> Vec<Chassis> {
        self.members.iter().map(|v| v.to_model()).collect()
    }

    pub fn is_liteon_powershelf(&self) -> bool {
        self.members.iter().any(|m| {
            m.chassis.id().into_inner() == "powershelf"
                || (m.chassis.id().into_inner() == "chassis"
                    && m.chassis
                        .hardware_id()
                        .manufacturer
                        .as_ref()
                        .is_some_and(|mfg| mfg.as_ref().to_lowercase().contains("lite-on")))
        })
    }

    pub fn liteon_power_state(&self) -> Option<LiteOnSuppliesState<'_>> {
        self.members.iter().find_map(|m| {
            m.oem_liteon_power_supplies
                .as_ref()
                .map(|v| LiteOnSuppliesState(v))
        })
    }

    pub fn is_gb300(&self) -> bool {
        self.members.iter().any(|m| {
            m.chassis.hardware_id().manufacturer == Some(Manufacturer::new("NVIDIA"))
                && m.chassis.hardware_id().model == Some(Model::new("NVIDIA GB300"))
        })
    }

    pub fn is_lenovo(&self) -> bool {
        self.members
            .iter()
            .any(|m| m.chassis.hardware_id().manufacturer == Some(Manufacturer::new("Lenovo")))
    }

    pub fn is_bluefield2(&self) -> bool {
        self.members
            .iter()
            .find(|c| c.chassis.id().into_inner() == "Card1")
            .is_some_and(|c| {
                let hw_id = c.chassis.hardware_id();
                hw_id.manufacturer == Some(Manufacturer::new("Nvidia"))
                    && hw_id.model == Some(Model::new("Bluefield 2 SmartNIC Main Card"))
            })
    }

    pub fn is_bluefield4(&self) -> bool {
        self.members.iter().any(|c| {
            c.chassis.hardware_id().model == Some(Model::new("B4240"))
                || c.chassis.hardware_id().model == Some(Model::new("B4240V"))
        })
    }

    pub fn dpu_card1_serial_number(&self) -> Result<Option<&str>, Error<B>> {
        let maybe_sn = self
            .members
            .iter()
            .find(|c| c.chassis.id().into_inner() == "Card1")
            .ok_or_else(Error::bmc_not_provided("chassis with id Card1"))?
            .chassis
            .hardware_id()
            .serial_number
            .map(|v| v.into_inner());
        Ok(maybe_sn)
    }

    // BF4 temporary PF0 fallback source:
    // read NDF0 PermanentMACAddress from known BF4 Redfish topology paths and
    // derive PF0 base MAC as (NDF0 - 0x10).
    // Remove callers once BF4 BMC exposes PF0 base MAC in ComputerSystem BaseMAC.
    pub fn dpu_bf4_ndf0_permanent_mac(&self) -> Option<BaseMac> {
        const BF4_NDF0_PATHS: [(&str, &str, &str); 2] = [
            // /redfish/v1/Chassis/BlueField_0/NetworkAdapters/BlueField_NIC_0/NetworkDeviceFunctions/0
            ("BlueField_0", "BlueField_NIC_0", "0"),
            // /redfish/v1/Chassis/Card1/NetworkAdapters/Bluefield_NIC/NetworkDeviceFunctions/0
            ("Card1", "Bluefield_NIC", "0"),
        ];
        for (chassis_id, adapter_id, function_id) in BF4_NDF0_PATHS {
            let mac = self
                .members
                .iter()
                .find(|c| c.chassis.id().into_inner() == chassis_id)
                .and_then(|c| {
                    c.network_adapters
                        .members()
                        .iter()
                        .find(|a| a.adapter.id().into_inner() == adapter_id)
                })
                .and_then(|adapter| adapter.functions.as_ref())
                .and_then(|functions| {
                    functions
                        .iter()
                        .find(|f| f.id().into_inner() == function_id)
                        .and_then(|f| f.ethernet_permanent_mac_address())
                });

            if let Some(mac) = mac
                && let Ok(parsed) = mac.as_str().parse::<MacAddress>()
            {
                let derived = mac_to_u64(parsed).checked_sub(BF4_NDF0_TO_BASE_MAC_OFFSET)?;
                return Some(u64_to_mac(derived).into());
            }
        }

        None
    }

    pub async fn pcie_devices(
        &self,
        chassis_filter: impl Fn(&ExploredChassis<B>) -> bool,
        limiter: &Semaphore,
    ) -> Result<Vec<PcieDevice<B>>, Error<B>> {
        // The per-chassis fetch futures are collected eagerly instead of
        // streamed through a `buffered` adapter: adapters over borrowed items
        // embed their closure types in the awaited future, which defeats
        // rustc's `Send` proof for the whole exploration ("implementation of
        // `FnOnce` is not general enough"). The shared limiter bounds the
        // real request fan-out either way.
        let fetches: Vec<_> = self
            .members
            .iter()
            .filter(|c| chassis_filter(c))
            .map(|c| async move {
                if let Some(collection) = limited(limiter, c.chassis.pcie_devices())
                    .await
                    .map_err(Error::nv_redfish("chassis pcie devices"))?
                {
                    limited(limiter, collection.members())
                        .await
                        .map_err(Error::nv_redfish("chassis pcie devices members"))
                } else {
                    Ok(Vec::new())
                }
            })
            .collect();
        let per_chassis: Vec<Vec<PcieDevice<B>>> = futures::future::try_join_all(fetches).await?;
        Ok(per_chassis.into_iter().flatten().collect())
    }
}

fn mac_to_u64(mac: MacAddress) -> u64 {
    mac.bytes()
        .iter()
        .fold(0u64, |acc, &byte| (acc << 8) | u64::from(byte))
}

fn u64_to_mac(value: u64) -> MacAddress {
    let b = value.to_be_bytes();
    MacAddress::new([b[2], b[3], b[4], b[5], b[6], b[7]])
}

pub struct ExploredChassis<B: Bmc> {
    pub chassis: NvChassis<B>,
    pub network_adapters: ExploredNetworkAdapterCollection<B>,
    pub assembly_sn: Option<String>,
    pub oem_liteon_power_supplies: Option<Vec<LiteOnPowerSupply>>,
}

impl<B: Bmc> ExploredChassis<B> {
    async fn explore(
        chassis: NvChassis<B>,
        config: &Config,
        limiter: &Semaphore,
    ) -> Result<Self, Error<B>> {
        // The network-adapter, assembly, and LiteOn power-supply subtrees of
        // one chassis are independent, so they proceed concurrently.
        let network_adapters_branch =
            ExploredNetworkAdapterCollection::explore(&chassis, &config.network_adapter, limiter);

        let assembly_branch = async {
            if let Some(model_check_fn) = (config.need_assembly_sn)(chassis.id()) {
                match limited(limiter, chassis.assembly()).await {
                    Ok(Some(assembly)) => {
                        let assembly_data = limited(limiter, assembly.assemblies())
                            .await
                            .map_err(Error::nv_redfish("chassis assemblies"))?;
                        Ok(assembly_data
                            .iter()
                            .find(|asm| model_check_fn(asm.hardware_id().model))
                            .and_then(|asm| asm.hardware_id().serial_number)
                            .map(|v| v.to_string()))
                    }
                    Ok(None) => Ok(None),
                    Err(err) => Err(Error::NvRedfish {
                        context: "chassis assembly",
                        err,
                    }),
                }
            } else {
                Ok(None)
            }
        };

        // Here we rely on the fact that
        // Chassis::oem_liteon_power_supply_links returns None
        // immediately if chassis is not LiteOn.
        let liteon_branch = async {
            if let Some(ps_links) = limited(limiter, chassis.oem_liteon_power_supply_links())
                .await
                .map_err(Error::nv_redfish("LiteOn power supply links"))?
            {
                let power_supplies = stream::iter(ps_links)
                    .map(|l| async move {
                        let ps = limited(limiter, l.fetch())
                            .await
                            .map_err(Error::nv_redfish("LiteOn power supply"))?;
                        Ok(LiteOnPowerSupply {
                            id: ps.base.id.clone(),
                            serial_number: ps
                                .serial_number
                                .clone()
                                .and_then(std::convert::identity),
                            power_state: ps.power_state,
                        })
                    })
                    .buffered(DEFAULT_MAX_CONCURRENT_BMC_REQUESTS)
                    .try_collect()
                    .await?;
                Ok(Some(power_supplies))
            } else {
                Ok(None)
            }
        };

        let (network_adapters, assembly_sn, oem_liteon_power_supplies) =
            tokio::try_join!(network_adapters_branch, assembly_branch, liteon_branch)?;

        Ok(Self {
            chassis,
            network_adapters,
            assembly_sn,
            oem_liteon_power_supplies,
        })
    }

    fn to_model(&self) -> Chassis {
        let network_adapters = self.network_adapters.to_model();
        let chassis_id = self.chassis.id();
        let hw_id = self.chassis.hardware_id();
        let serial_number = self
            .assembly_sn
            .clone()
            .or(hw_id.serial_number.map(|v| v.to_string()))
            .map(|s| s.trim().to_string());

        let nvidia_oem = self
            .chassis
            .oem_nvidia_baseboard_cbc()
            .ok()
            .and_then(identity);
        Chassis {
            id: chassis_id.to_string(),
            manufacturer: hw_id.manufacturer.map(|v| v.to_string()),
            model: hw_id.model.map(|v| v.to_string()),
            part_number: hw_id.part_number.map(|v| v.to_string()),
            serial_number,
            network_adapters,
            physical_slot_number: nvidia_oem
                .as_ref()
                .and_then(|x| x.chassis_physical_slot_number())
                .map(|v| v.into_inner() as i32),
            compute_tray_index: nvidia_oem
                .as_ref()
                .and_then(|x| x.compute_tray_index())
                .map(|v| v.into_inner() as i32),
            topology_id: nvidia_oem
                .as_ref()
                .and_then(|x| x.topology_id())
                .map(|v| v.into_inner() as i32),
            revision_id: nvidia_oem
                .as_ref()
                .and_then(|x| x.revision_id())
                .map(|v| v.into_inner() as i32),
        }
    }
}

pub struct LiteOnPowerSupply {
    pub id: String,
    pub serial_number: Option<String>,
    pub power_state: Option<bool>,
}

pub struct LiteOnSuppliesState<'a>(&'a [LiteOnPowerSupply]);

impl fmt::Display for LiteOnSuppliesState<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0
            .iter()
            .map(|s| format!("{}:{:?}:{:?}", s.id, s.serial_number, s.power_state))
            .join(", ")
            .fmt(f)
    }
}

impl LiteOnSuppliesState<'_> {
    pub fn to_model(&self) -> ModelPowerState {
        if self.0.is_empty() {
            return ModelPowerState::Unknown;
        }

        let on = self.0.iter().all(|v| v.power_state == Some(true));
        let off = self.0.iter().all(|v| v.power_state == Some(false));
        if on {
            ModelPowerState::On
        } else if off {
            ModelPowerState::Off
        } else {
            tracing::warn!("powershelf power state is unknown: {self}");
            ModelPowerState::Unknown
        }
    }
}
